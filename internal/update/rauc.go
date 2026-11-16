// Package update delegates bundle installation to the system RAUC service.
package update

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	service     = "de.pengutronix.rauc"
	installer   = "de.pengutronix.rauc.Installer"
	properties  = "org.freedesktop.DBus.Properties"
	callTimeout = 3 * time.Second
)

var ErrBusy = errors.New("RAUC is busy")

type Progress struct {
	Percentage int32  `json:"percentage"`
	Message    string `json:"message"`
	Depth      int32  `json:"depth"`
}

type Status struct {
	Operation string   `json:"operation"`
	Progress  Progress `json:"progress"`
	LastError string   `json:"last_error"`
	Pending   bool     `json:"pending"`
	Path      string   `json:"path,omitempty"`
	Result    *int32   `json:"result"`
}

type methodCaller interface {
	CallWithContext(context.Context, string, dbus.Flags, ...interface{}) *dbus.Call
}

type dialResult struct {
	conn *dbus.Conn
	err  error
}

// Client is lazy: creating it does not connect to the bus or require RAUC.
// It serializes its calls and keeps only the latest local submission in memory.
type Client struct {
	mu              sync.Mutex
	conn            *dbus.Conn
	object          methodCaller
	owner           string
	completed       chan *dbus.Signal
	observed        dbus.Sequence
	completionAfter dbus.Sequence
	pending         bool
	path            string
	result          *int32
	closed          bool
	bootSlot        string
	busAddress      string
	persistent      *tracker
	dialing         chan dialResult
	done            chan struct{}
}

func New() *Client { return &Client{} }

// connect uses godbus's native Unix transport, and closes the private
// connection if authentication/Hello exceeds the calling context's deadline.
func (c *Client) connect(ctx context.Context) error {
	if c.closed {
		return errors.New("RAUC client is closed")
	}
	if c.object != nil && (c.conn == nil || c.conn.Connected()) {
		return nil
	}
	if c.conn != nil {
		c.disconnect()
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	fail := func(err error) error { _ = conn.Close(); return err }
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = conn.Close(); close(finished) })
	if err = conn.Auth(nil); err == nil {
		err = conn.Hello()
	}
	if !stop() {
		<-finished
		return fail(ctx.Err())
	}
	if err != nil {
		return fail(err)
	}
	var owner string
	if err = conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", dbus.FlagNoAutoStart, service).Store(&owner); err != nil {
		return fail(err)
	}
	completed := make(chan *dbus.Signal, 8)
	conn.Signal(completed)
	if err = conn.AddMatchSignalContext(ctx, dbus.WithMatchSender(owner), dbus.WithMatchObjectPath("/"), dbus.WithMatchInterface(installer), dbus.WithMatchMember("Completed")); err != nil {
		return fail(err)
	}
	c.conn, c.object, c.owner, c.completed = conn, conn.Object(owner, "/"), owner, completed
	return nil
}

// Retain at most one native Unix dial even if the socket backlog stalls.
// Callers have deadlines; closing Client also cleans up a late connection.
func (c *Client) dial(ctx context.Context) (*dbus.Conn, error) {
	if c.done == nil {
		c.done = make(chan struct{})
	}
	if c.dialing == nil {
		c.dialing = make(chan dialResult)
		result, done := c.dialing, c.done
		go func() {
			address := c.busAddress
			if address == "" {
				address = "unix:path=/run/dbus/system_bus_socket"
			}
			conn, err := dbus.Dial(address)
			select {
			case result <- dialResult{conn, err}:
			case <-done:
				if conn != nil {
					_ = conn.Close()
				}
			}
		}()
	}
	select {
	case result := <-c.dialing:
		c.dialing = nil
		return result.conn, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Client) disconnect() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.conn, c.object, c.completed, c.owner = nil, nil, nil, ""
	// A lost subscription cannot prove that an old install succeeded.
	c.pending, c.result, c.observed, c.completionAfter = false, nil, 0, 0
}

func ownerGone(err error) bool {
	var remote dbus.Error
	var pointer *dbus.Error
	if errors.As(err, &pointer) {
		remote = *pointer
	} else if !errors.As(err, &remote) {
		return false
	}
	return remote.Name == "org.freedesktop.DBus.Error.ServiceUnknown" || remote.Name == "org.freedesktop.DBus.Error.NameHasNoOwner" || remote.Name == "org.freedesktop.DBus.Error.Disconnected"
}

func (c *Client) consumeCompleted() error {
	for {
		select {
		case signal, ok := <-c.completed:
			if !ok {
				return errors.New("RAUC signal connection closed")
			}
			if signal == nil || signal.Sender != c.owner || signal.Path != "/" || signal.Name != installer+".Completed" {
				continue
			}
			if len(signal.Body) != 1 {
				return errors.New("invalid RAUC Completed signal")
			}
			result, ok := signal.Body[0].(int32)
			if !ok {
				return errors.New("invalid RAUC completion code")
			}
			if c.pending && signal.Sequence > c.completionAfter {
				c.pending, c.result = false, &result
			}
		default:
			return nil
		}
	}
}

func (c *Client) status(ctx context.Context) (Status, error) {
	if err := ctx.Err(); err != nil {
		return Status{}, err
	}
	if err := c.connect(ctx); err != nil {
		return Status{}, fmt.Errorf("connect RAUC: %w", err)
	}
	call := c.object.CallWithContext(ctx, properties+".GetAll", dbus.FlagNoAutoStart, installer)
	if call.Err != nil {
		if ownerGone(call.Err) || (c.conn != nil && !c.conn.Connected()) {
			c.disconnect() // Next request reconnects and resolves the new owner.
		}
		return Status{}, call.Err
	}
	c.observed = call.ResponseSequence
	if len(call.Body) != 1 {
		return Status{}, errors.New("invalid RAUC properties response")
	}
	values, ok := call.Body[0].(map[string]dbus.Variant)
	if !ok {
		return Status{}, errors.New("invalid RAUC properties dictionary")
	}
	c.bootSlot, _ = values["BootSlot"].Value().(string)
	operation, operationOK := values["Operation"].Value().(string)
	lastError, lastErrorOK := values["LastError"].Value().(string)
	progress, progressOK := values["Progress"].Value().([]interface{})
	if !operationOK || operation == "" || !lastErrorOK || !progressOK || len(progress) != 3 {
		return Status{}, errors.New("invalid RAUC status properties")
	}
	percentage, pOK := progress[0].(int32)
	message, mOK := progress[1].(string)
	depth, dOK := progress[2].(int32)
	if !pOK || !mOK || !dOK {
		return Status{}, errors.New("invalid RAUC progress structure")
	}
	if err := c.consumeCompleted(); err != nil {
		return Status{}, err
	}
	return Status{Operation: operation, Progress: Progress{percentage, message, depth}, LastError: lastError, Pending: c.pending, Path: c.path, Result: c.result}, nil
}

func (c *Client) Status(ctx context.Context) (Status, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	status, err := c.status(ctx)
	if c.persistent != nil && c.persistent.active != "" {
		status.Pending = true
	}
	return status, err
}

func (c *Client) Busy(ctx context.Context) (bool, error) {
	status, err := c.Status(ctx)
	return status.Pending || status.Operation != "idle", err
}

// Install only requests installation. Nil means RAUC accepted the request;
// completion (including signature/compatibility failures) is asynchronous.
func (c *Client) Install(ctx context.Context, path string) error {
	if c.persistent != nil {
		_, err := c.InstallRequest(ctx, path, "")
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	status, err := c.status(ctx)
	if err != nil {
		return err
	}
	if status.Pending || status.Operation != "idle" {
		return ErrBusy
	}
	// No ignore-compatible, insecure or skip-verification options are exposed.
	// Reserve before sending: a transport timeout can leave installation
	// accepted remotely even though its reply was not observed locally.
	c.pending, c.path, c.result = true, path, nil
	c.completionAfter = c.observed
	call := c.object.CallWithContext(ctx, installer+".InstallBundle", dbus.FlagNoAutoStart, path, map[string]dbus.Variant{})
	if call.Err != nil {
		if ownerGone(call.Err) || (c.conn != nil && !c.conn.Connected()) {
			c.disconnect()
			return call.Err
		}
		var remote dbus.Error
		var remotePointer *dbus.Error
		if errors.As(call.Err, &remotePointer) {
			remote = *remotePointer
		} else if !errors.As(call.Err, &remote) {
			return call.Err // Acceptance is uncertain; keep the reboot guard.
		}
		// This fixed RAUC version reports busy through a generic GIO error.
		// Its busy branch also resets Operation, so retain the guard until
		// the already running installation's real Completed signal arrives.
		if len(remote.Body) == 1 && remote.Body[0] == "Already processing a different method" {
			c.path = ""
			return fmt.Errorf("%w: %v", ErrBusy, call.Err)
		}
		c.pending = false
		return call.Err
	}
	return nil
}

func (c *Client) Close() error {
	if c.persistent != nil {
		c.persistent.cancel()
		<-c.persistent.done
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed && c.done != nil {
		close(c.done)
	}
	c.closed = true
	if c.persistent != nil {
		c.releaseTask()
	}
	if c.conn != nil {
		err := c.conn.Close()
		c.conn, c.object = nil, nil
		return err
	}
	return nil
}
