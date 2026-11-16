package watchdog

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

type fake struct {
	node                  syscall.Stat_t
	openCount, closeCount int
	flags                 int
	requests              []uintptr
	writes                []byte
	timeout               int32
	requested             int32
	stopErr               error
	setErr                error
	writeErr              error
	shortWrite            bool
	postStatErr           error
	block, entered        chan struct{}
}

func newFake() *fake {
	return &fake{node: syscall.Stat_t{Mode: syscall.S_IFCHR, Rdev: 0xf200, Dev: 7, Ino: 8}, timeout: 44}
}
func (f *fake) lstat(string) (syscall.Stat_t, error) { return f.node, nil }
func (f *fake) open(_ string, flags int) (rawHandle, error) {
	f.openCount++
	f.flags = flags
	return f, nil
}
func (f *fake) stat() (syscall.Stat_t, error) { return f.node, f.postStatErr }
func (f *fake) close() error                  { f.closeCount++; return nil }
func (f *fake) write(b []byte) (int, error) {
	f.writes = append(f.writes, b...)
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	if f.shortWrite {
		return 0, nil
	}
	return len(b), nil
}
func (f *fake) ioctl(request uintptr, arg unsafe.Pointer) error {
	f.requests = append(f.requests, request)
	switch request {
	case getSupport:
		w := (*wireInfo)(arg)
		w.Options = OptionKeepalive | OptionSetTimeout | OptionMagicClose
		copy(w.Identity[:], "mock watchdog")
	case getTimeout:
		*(*int32)(arg) = f.timeout
	case setTimeout:
		f.requested = *(*int32)(arg)
		if f.setErr != nil {
			return f.setErr
		}
		f.timeout = 44
		*(*int32)(arg) = 44
	case keepalive:
		if f.entered != nil {
			close(f.entered)
			<-f.block
			f.entered = nil
		}
	case setOptions:
		if *(*int32)(arg) != DisableCard {
			return errors.New("wrong disable options")
		}
		return f.stopErr
	default:
		return errors.New("unexpected ioctl")
	}
	return nil
}
func opened(t *testing.T, f *fake) *Device {
	t.Helper()
	d, err := openWith(f, "/dev/watchdog0", 0xf200)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestUAPIWidthsAndCommands(t *testing.T) {
	if unsafe.Sizeof(wireInfo{}) != 40 || unsafe.Sizeof(int32(0)) != 4 {
		t.Fatal("UAPI struct or C int width mismatch")
	}
	if getSupport != 0x80285700 || setOptions != 0x80045704 || keepalive != 0x80045705 || setTimeout != 0xc0045706 || getTimeout != 0x80045707 {
		t.Fatal("Linux UAPI ioctl mismatch")
	}
}
func TestOpenIsExplicitAndDoesNotInitializeOrFeed(t *testing.T) {
	f := newFake()
	d := opened(t, f)
	if f.openCount != 1 || f.flags != syscall.O_WRONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW || len(f.requests) != 0 {
		t.Fatal("open flags or hidden initialization")
	}
	r, err := d.CloseWithoutStopping()
	if err != nil || !r.FDClosed || r.UserWatchdogDisabled || f.closeCount != 1 || len(f.requests) != 0 {
		t.Fatal("explicit release unexpectedly disabled watchdog")
	}
}
func TestSupportTimeoutReadbackAndFeed(t *testing.T) {
	f := newFake()
	d := opened(t, f)
	s, err := d.Support()
	if err != nil || s.Identity != "mock watchdog" || !s.CanSetTimeout || !s.HasMagicClose || !s.CanKeepalive {
		t.Fatal("support decode failed")
	}
	n, err := d.SetTimeout(30)
	if err != nil || n != 44 || f.requested != 30 {
		t.Fatal("effective timeout not read back")
	}
	if err := d.KeepAlive(); err != nil {
		t.Fatal(err)
	}
	want := []uintptr{getSupport, setTimeout, getTimeout, keepalive}
	if !reflect.DeepEqual(f.requests, want) {
		t.Fatal("wrong ioctl sequence")
	}
	r, err := d.StopUserAndClose()
	if err != nil || !r.UserWatchdogDisabled || !r.FDClosed || r.HardwareStoppedConfirmed {
		t.Fatal("stop must not claim hardware confirmation")
	}
	if err := d.KeepAlive(); !errors.Is(err, ErrClosed) {
		t.Fatal("feed after close was not rejected")
	}
}
func TestFailedStopRetainsOwnerAndAllowsRetry(t *testing.T) {
	f := newFake()
	d := opened(t, f)
	f.stopErr = syscall.EBUSY
	r, err := d.StopUserAndClose()
	if !errors.Is(err, syscall.EBUSY) || r.FDClosed || f.closeCount != 0 {
		t.Fatal("failed stop lost ownership")
	}
	if err := d.KeepAlive(); err != nil {
		t.Fatal("failed-stop handle cannot feed")
	}
	f.stopErr = nil
	r, err = d.StopUserAndClose()
	if err != nil || !r.FDClosed || f.closeCount != 1 {
		t.Fatal("retry failed")
	}
}

func TestRepeatedCloseDoesNotOperateOnReusedDescriptor(t *testing.T) {
	f := newFake()
	d := opened(t, f)
	if _, err := d.StopUserAndClose(); err != nil {
		t.Fatal(err)
	}
	for _, closeAgain := range []func() (CloseResult, error){d.StopUserAndClose, d.MagicClose, d.CloseWithoutStopping} {
		if _, err := closeAgain(); !errors.Is(err, ErrClosed) {
			t.Fatal("duplicate close was not rejected")
		}
	}
	if f.closeCount != 1 || !reflect.DeepEqual(f.requests, []uintptr{setOptions}) || len(f.writes) != 0 {
		t.Fatal("duplicate close touched a potentially reused fd")
	}
}
func TestMagicCloseIsSeparateAndDoesNotClaimStop(t *testing.T) {
	f := newFake()
	d := opened(t, f)
	r, err := d.MagicClose()
	if err != nil || !r.FDClosed || !r.MagicCloseWritten || r.UserWatchdogDisabled || r.HardwareStoppedConfirmed || string(f.writes) != "V" || len(f.requests) != 0 {
		t.Fatal("magic close semantics differ")
	}
}
func TestShortMagicWriteKeepsHandle(t *testing.T) {
	f := newFake()
	f.shortWrite = true
	d := opened(t, f)
	r, err := d.MagicClose()
	if err == nil || r.FDClosed || f.closeCount != 0 {
		t.Fatal("short magic write closed fd")
	}
	d.CloseWithoutStopping()
}
func TestFailuresDoNotFeedOrCloseBehindCaller(t *testing.T) {
	f := newFake()
	d := opened(t, f)
	f.setErr = syscall.EINVAL
	if _, err := d.SetTimeout(30); !errors.Is(err, syscall.EINVAL) {
		t.Fatal("SETTIMEOUT error was lost")
	}
	if _, err := d.SetTimeout(0); err == nil {
		t.Fatal("zero timeout accepted")
	}
	if f.closeCount != 0 || len(f.requests) != 1 {
		t.Fatal("unexpected hidden operation after error")
	}
	d.CloseWithoutStopping()
}
func TestPostOpenFailureClosesFDAndReportsUncertainState(t *testing.T) {
	f := newFake()
	f.postStatErr = syscall.EIO
	d, err := openWith(f, "/dev/watchdog0", 0xf200)
	if err == nil || d != nil || f.closeCount != 1 || len(f.requests) != 0 {
		t.Fatal("post-open error ownership result differs")
	}
}
func TestOrdinaryFileAndSymlinkRejectedBeforeOpening(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "watchdog0")
	if err := os.WriteFile(regular, []byte("never open as watchdog"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateCharacterNode(regular); err == nil {
		t.Fatal("ordinary file accepted")
	}
	if _, err := openWith(system{}, regular, 0xf200); err == nil {
		t.Fatal("ordinary file open accepted")
	}
	link := filepath.Join(dir, "watchdog1")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateCharacterNode(link); err == nil {
		t.Fatal("symlink accepted")
	}
	f := newFake()
	f.node.Mode = syscall.S_IFLNK
	if _, err := openWith(f, "/dev/watchdog0", 0xf200); err == nil || f.openCount != 0 {
		t.Fatal("symlink reached open")
	}
}
func TestConcurrentFeedAndCloseAreSerialized(t *testing.T) {
	f := newFake()
	f.block = make(chan struct{})
	f.entered = make(chan struct{})
	d := opened(t, f)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := d.KeepAlive(); err != nil {
			t.Error(err)
		}
	}()
	<-f.entered
	closed := make(chan struct{})
	go func() {
		defer wg.Done()
		defer close(closed)
		if _, err := d.StopUserAndClose(); err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-closed:
		t.Fatal("closed while feed was in flight")
	case <-time.After(20 * time.Millisecond):
	}
	close(f.block)
	wg.Wait()
	if f.closeCount != 1 || !reflect.DeepEqual(f.requests, []uintptr{keepalive, setOptions}) {
		t.Fatal("feed/close order differs")
	}
}
