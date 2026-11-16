package update

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/godbus/dbus/v5"
)

type fakeRAUC struct {
	operation   string
	installErr  error
	statusErr   error
	properties  []interface{}
	methods     []string
	installPath string
}

func (f *fakeRAUC) CallWithContext(ctx context.Context, method string, flags dbus.Flags, args ...interface{}) *dbus.Call {
	f.methods = append(f.methods, method)
	if flags != dbus.FlagNoAutoStart {
		panic("RAUC should not be auto-started")
	}
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded D-Bus method")
	}
	if method == installer+".InstallBundle" {
		f.installPath = args[0].(string)
		if options, ok := args[1].(map[string]dbus.Variant); !ok || len(options) != 0 {
			panic("installation options must stay empty")
		}
		return &dbus.Call{Err: f.installErr}
	}
	if method != properties+".GetAll" || !reflect.DeepEqual(args, []interface{}{installer}) {
		panic("unexpected RAUC method")
	}
	if f.statusErr != nil {
		return &dbus.Call{Err: f.statusErr}
	}
	if f.properties != nil {
		return &dbus.Call{Body: f.properties}
	}
	return &dbus.Call{ResponseSequence: 10, Body: []interface{}{map[string]dbus.Variant{
		"Operation": dbus.MakeVariant(f.operation),
		"LastError": dbus.MakeVariant(""),
		"Progress":  dbus.MakeVariantWithSignature([]interface{}{int32(25), "writing", int32(2)}, dbus.ParseSignatureMust("(isi)")),
	}}}
}

func fakeClient(f *fakeRAUC) *Client {
	return &Client{object: f, owner: ":1.41", completed: make(chan *dbus.Signal, 8)}
}

func completed(result int32) *dbus.Signal {
	return &dbus.Signal{Sender: ":1.41", Path: "/", Name: installer + ".Completed", Body: []interface{}{result}, Sequence: 11}
}

func TestAcceptedIsPendingUntilActualCompleted(t *testing.T) {
	f := &fakeRAUC{operation: "idle"}
	c := fakeClient(f)
	if err := c.Install(context.Background(), "/userdata/update.raucb"); err != nil {
		t.Fatal(err)
	}
	status, err := c.Status(context.Background())
	if err != nil || !status.Pending || status.Result != nil || status.Path != f.installPath || status.Progress.Percentage != 25 {
		t.Fatalf("accepted falsely completed: %+v %v", status, err)
	}
	// Even if RAUC's Operation was erroneously reset by another rejected
	// caller, the Core-local accepted installation still blocks reboot.
	if busy, err := c.Busy(context.Background()); err != nil || !busy {
		t.Fatalf("accepted install did not stay busy: %v %v", busy, err)
	}
	c.completed <- completed(1)
	status, err = c.Status(context.Background())
	if err != nil || status.Pending || status.Result == nil || *status.Result != 1 {
		t.Fatalf("real failure completion lost: %+v %v", status, err)
	}
	if busy, err := c.Busy(context.Background()); err != nil || busy {
		t.Fatalf("completed installation stayed busy: %v %v", busy, err)
	}
}

func TestOtherInstallerBusyIsNotSubmittedAgain(t *testing.T) {
	f := &fakeRAUC{operation: "installing"}
	c := fakeClient(f)
	if err := c.Install(context.Background(), "/userdata/update.raucb"); !errors.Is(err, ErrBusy) {
		t.Fatalf("not classified busy: %v", err)
	}
	if f.installPath != "" {
		t.Fatal("second installer was submitted")
	}
}

func TestDelayedOldCompletionCannotCompleteNewInstallation(t *testing.T) {
	c := fakeClient(&fakeRAUC{operation: "idle"})
	if err := c.Install(context.Background(), "/userdata/new.raucb"); err != nil {
		t.Fatal(err)
	}
	old := completed(0)
	old.Sequence = 9 // Received before the pre-install GetAll reply, delivered late.
	c.completed <- old
	status, err := c.Status(context.Background())
	if err != nil || !status.Pending || status.Result != nil {
		t.Fatalf("an older signal completed a newer request: %+v %v", status, err)
	}
}

func TestBusyRaceIsClassifiedAndGuarded(t *testing.T) {
	f := &fakeRAUC{operation: "idle", installErr: dbus.Error{Name: "org.gtk.GDBus.UnmappedGError.Quark._g_2dio_2derror_2dquark.Code30", Body: []interface{}{"Already processing a different method"}}}
	c := fakeClient(f)
	if err := c.Install(context.Background(), "/userdata/update.raucb"); !errors.Is(err, ErrBusy) {
		t.Fatalf("race not classified busy: %v", err)
	}
	if busy, err := c.Busy(context.Background()); err != nil || !busy {
		t.Fatalf("busy rejection unexpectedly released reboot guard: %v %v", busy, err)
	}
	c.completed <- completed(0)
	if busy, err := c.Busy(context.Background()); err != nil || busy {
		t.Fatalf("completion did not release busy guard: %v %v", busy, err)
	}
}

func TestTransportTimeoutDoesNotClaimRejectionOrSuccess(t *testing.T) {
	f := &fakeRAUC{operation: "idle", installErr: context.DeadlineExceeded}
	c := fakeClient(f)
	if err := c.Install(context.Background(), "/userdata/update.raucb"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	status, err := c.Status(context.Background())
	if err != nil || !status.Pending || status.Result != nil {
		t.Fatalf("uncertain remote acceptance lost: %+v %v", status, err)
	}
}

func TestInvalidDBusPropertiesReturnErrors(t *testing.T) {
	for _, body := range [][]interface{}{{}, {"bad properties"}, {map[string]dbus.Variant{}}} {
		c := fakeClient(&fakeRAUC{properties: body})
		if _, err := c.Status(context.Background()); err == nil {
			t.Fatalf("accepted invalid response: %#v", body)
		}
	}
}

func TestCanceledCallDoesNotTouchDBus(t *testing.T) {
	f := &fakeRAUC{operation: "idle"}
	c := fakeClient(f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Status(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(f.methods) != 0 {
		t.Fatal("canceled call touched D-Bus")
	}
}

func TestLostRAUCOwnerIsInvalidatedAndNeverInventsSuccess(t *testing.T) {
	f := &fakeRAUC{operation: "idle"}
	c := fakeClient(f)
	if err := c.Install(context.Background(), "/userdata/update.raucb"); err != nil {
		t.Fatal(err)
	}
	f.statusErr = dbus.Error{Name: "org.freedesktop.DBus.Error.ServiceUnknown"}
	if _, err := c.Status(context.Background()); err == nil {
		t.Fatal("missing service unexpectedly succeeded")
	}
	if c.object != nil || c.owner != "" || c.result != nil || c.pending {
		t.Fatal("lost owner or unconfirmed installation was retained as known")
	}
	// Simulate the new lazy connection, which resolves a fresh unique owner.
	c.object, c.owner, c.completed = &fakeRAUC{operation: "idle"}, ":1.42", make(chan *dbus.Signal, 8)
	status, err := c.Status(context.Background())
	if err != nil || status.Result != nil || status.Pending || status.Operation != "idle" {
		t.Fatalf("new owner did not recover with unknown old result: %+v %v", status, err)
	}
}
