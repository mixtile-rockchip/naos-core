// Package container implements the fixed naosd List protocol over a Unix socket.
package container

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	maximumFrame          = 1024 * 1024
	maximumListBytes      = 256 * 1024
	maximumStates         = 64
	maximumResponseFrames = 66
	callTimeout           = 3 * time.Second
)

type State struct {
	ID               string `json:"id"`
	PID              uint64 `json:"pid"`
	Running          bool   `json:"running"`
	Status           string `json:"status"`
	Bundle           string `json:"bundle"`
	Rootfs           string `json:"rootfs"`
	Created          string `json:"created"`
	Owner            string `json:"owner"`
	CgroupPath       string `json:"cgroup_path"`
	ProcessStartTime uint64 `json:"process_start_time"`
}

type Client struct {
	Socket string
}

func (c Client) List(ctx context.Context) ([]State, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return nil, fmt.Errorf("connect naosd: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	states, err := list(conn)
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return states, err
}

func list(conn io.ReadWriter) ([]State, error) {
	// SocketFrame: REQUEST=1, method="List", empty payload, version=1.
	if err := writeFrame(conn, []byte("\x08\x01\x12\x04List\x30\x01")); err != nil {
		return nil, fmt.Errorf("send List: %w", err)
	}
	states := make([]State, 0)
	total := 0
	for count := 0; count < maximumResponseFrames; count++ {
		f, err := readFrame(conn)
		if err != nil {
			return nil, fmt.Errorf("List response before RESULT: %w", err)
		}
		if f.Method != "" && f.Method != "List" {
			return nil, errors.New("naosd response method differs from List")
		}
		switch f.Kind {
		case 2: // DATA
			total += len(f.Payload)
			if len(states) >= maximumStates || total > maximumListBytes {
				return nil, errors.New("naosd List exceeds 64 states or 256 KiB")
			}
			state, err := decodeState(f.Payload)
			if err != nil {
				return nil, fmt.Errorf("decode naosd state: %w", err)
			}
			states = append(states, state)
		case 4: // RESULT
			if f.Code != 0 {
				return nil, fmt.Errorf("naosd List failed (code %d): %.256s", f.Code, f.Message)
			}
			return states, nil
		default:
			return nil, errors.New("naosd List expected DATA or RESULT")
		}
	}
	return nil, errors.New("naosd List response frame count exceeded")
}
