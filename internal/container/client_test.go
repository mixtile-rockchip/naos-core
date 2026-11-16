package container

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func encodedFrame(kind, code uint64, payload []byte) []byte {
	data := binary.AppendUvarint(nil, 8)
	data = binary.AppendUvarint(data, kind)
	if len(payload) != 0 {
		data = append(data, 26)
		data = binary.AppendUvarint(data, uint64(len(payload)))
		data = append(data, payload...)
	}
	if code != 0 {
		data = append(data, 32)
		data = binary.AppendUvarint(data, code)
	}
	return append(data, 48, 1)
}

func serveList(t *testing.T, serve func(net.Conn) error) (Client, <-chan error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "naosd.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		request, err := readFrame(conn)
		if err == nil && (request.Kind != 1 || request.Method != "List" || len(request.Payload) != 0) {
			err = fmt.Errorf("incorrect List request: %+v", request)
		}
		if err == nil {
			err = serve(conn)
		}
		done <- err
	}()
	return Client{Socket: path}, done
}

func TestListEmptyIsJSONArray(t *testing.T) {
	client, done := serveList(t, func(conn net.Conn) error {
		return writeFrame(conn, encodedFrame(4, 0, nil))
	})
	states, err := client.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(states)
	if err != nil || string(data) != "[]" {
		t.Fatalf("empty list encoded as %s, err=%v", data, err)
	}
}

func TestListDecodesStateAndRequiresResult(t *testing.T) {
	state := []byte{10, 4, 'd', 'e', 'm', 'o', 16, 42, 24, 1, 34, 7, 'r', 'u', 'n', 'n', 'i', 'n', 'g', 80}
	state = binary.AppendUvarint(state, 9007199254740993)
	client, done := serveList(t, func(conn net.Conn) error {
		if err := writeFrame(conn, encodedFrame(2, 0, state)); err != nil {
			return err
		}
		return writeFrame(conn, encodedFrame(4, 0, nil))
	})
	states, err := client.List(context.Background())
	if err != nil || len(states) != 1 {
		t.Fatalf("states=%+v, err=%v", states, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	got := states[0]
	if got.ID != "demo" || got.PID != 42 || !got.Running || got.Status != "running" || got.ProcessStartTime != 9007199254740993 {
		t.Fatalf("state fields differ: %+v", got)
	}
}

func TestListRejectsIncompleteOrFailedResponse(t *testing.T) {
	cases := []struct {
		name, want string
		serve      func(net.Conn) error
	}{
		{"eof", "before RESULT", func(conn net.Conn) error { return writeFrame(conn, encodedFrame(2, 0, nil)) }},
		{"remoteError", "code 5", func(conn net.Conn) error { return writeFrame(conn, encodedFrame(4, 5, nil)) }},
		{"oversize", "frame length", func(conn net.Conn) error {
			var header [4]byte
			binary.BigEndian.PutUint32(header[:], maximumFrame+1)
			_, err := conn.Write(header[:])
			return err
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client, done := serveList(t, c.serve)
			states, err := client.List(context.Background())
			if err == nil || !strings.Contains(err.Error(), c.want) || len(states) != 0 {
				t.Fatalf("states=%+v error=%v; want %q", states, err, c.want)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestListCancellationClosesPendingResponse(t *testing.T) {
	ready := make(chan struct{})
	client, done := serveList(t, func(conn net.Conn) error {
		close(ready)
		var one [1]byte
		_, err := conn.Read(one[:])
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-ready; cancel() }()
	if _, err := client.List(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
