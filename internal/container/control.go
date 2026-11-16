package container

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

var ErrInvalidID = errors.New("container id must be 1..128 ASCII letters, digits, dot, underscore or hyphen, starting with a letter or digit")

func ValidID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for i := range id {
		b := id[i]
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' {
			continue
		}
		if i == 0 || b != '.' && b != '_' && b != '-' {
			return false
		}
	}
	return true
}

type RemoteError struct {
	Code    uint64
	Message string
}

func (e *RemoteError) Error() string {
	return fmt.Sprintf("naosd operation failed (code %d): %.256s", e.Code, e.Message)
}

// Change sends one explicit operation. It never starts the daemon or retries
// an ambiguous operation after a disconnect or timeout.
func (c Client) Change(ctx context.Context, id, action string) error {
	if !ValidID(id) {
		return ErrInvalidID
	}
	var method string
	switch action {
	case "start":
		method = "Start"
	case "stop":
		method = "Stop"
	case "restart":
		method = "Restart"
	default:
		return errors.New("unsupported container operation")
	}
	return c.control(ctx, method, id)
}

// StartManifest asks naosd to load an external container directory in memory.
// It does not install a package, change autorun, or retry an ambiguous Start.
func (c Client) StartManifest(ctx context.Context, path string) error {
	if len(path) > 4096 || !strings.HasPrefix(path, "/userdata/") || filepath.Clean(path) != path || filepath.Base(path) != "manifest.yml" || strings.ContainsFunc(path, unicode.IsControl) {
		return errors.New("container manifest must be a clean /userdata/ path ending in manifest.yml")
	}
	return c.control(ctx, "Start", path)
}

func (c Client) control(ctx context.Context, method, value string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return fmt.Errorf("connect naosd: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	// Payload is google.protobuf.StringValue; the outer message is SocketFrame.
	payload := binary.AppendUvarint([]byte{10}, uint64(len(value)))
	payload = append(payload, value...)
	request := []byte{8, 1, 18}
	request = binary.AppendUvarint(request, uint64(len(method)))
	request = append(request, method...)
	request = append(request, 26)
	request = binary.AppendUvarint(request, uint64(len(payload)))
	request = append(request, payload...)
	request = append(request, 48, 1)
	if err := writeFrame(conn, request); err != nil {
		return fmt.Errorf("send %s: %w", method, err)
	}
	response, err := readFrame(conn)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%s response before RESULT: %w", method, err)
	}
	if response.Kind != 4 || response.Method != "" && response.Method != method {
		return errors.New("naosd control response is not the matching RESULT")
	}
	if response.Code != 0 {
		return &RemoteError{Code: response.Code, Message: response.Message}
	}
	return nil
}
