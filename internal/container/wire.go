package container

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
	"unicode/utf8"
)

type frame struct {
	Kind, Code, Version uint64
	Method, Message     string
	Payload             []byte
}

type field struct {
	number, wire, value uint64
	bytes               []byte
}

// Only the protobuf primitives used by the fixed SocketFrame/State schemas.
func fields(data []byte, visit func(field) error) error {
	for len(data) != 0 {
		key, n := binary.Uvarint(data)
		if n <= 0 || key>>3 == 0 || key>>3 > (1<<29)-1 {
			return errors.New("invalid protobuf field key")
		}
		data = data[n:]
		f := field{number: key >> 3, wire: key & 7}
		switch f.wire {
		case 0:
			value, used := binary.Uvarint(data)
			if used <= 0 {
				return errors.New("invalid protobuf varint")
			}
			f.value, data = value, data[used:]
		case 1:
			if len(data) < 8 {
				return io.ErrUnexpectedEOF
			}
			data = data[8:]
		case 2:
			length, used := binary.Uvarint(data)
			if used <= 0 || length > uint64(len(data)-used) {
				return errors.New("invalid protobuf byte length")
			}
			data = data[used:]
			f.bytes, data = data[:int(length)], data[int(length):]
		case 5:
			if len(data) < 4 {
				return io.ErrUnexpectedEOF
			}
			data = data[4:]
		default:
			return errors.New("unsupported protobuf wire type")
		}
		if err := visit(f); err != nil {
			return err
		}
	}
	return nil
}

func textField(f field) (string, error) {
	if f.wire != 2 || !utf8.Valid(f.bytes) {
		return "", errors.New("invalid protobuf UTF-8 string field")
	}
	return string(f.bytes), nil
}

func integerField(f field) (uint64, error) {
	if f.wire != 0 {
		return 0, errors.New("invalid protobuf integer field")
	}
	return f.value, nil
}

func decode(data []byte) (f frame, err error) {
	err = fields(data, func(v field) (err error) {
		switch v.number {
		case 1:
			f.Kind, err = integerField(v)
		case 2:
			f.Method, err = textField(v)
		case 3:
			if v.wire != 2 {
				return errors.New("invalid frame payload")
			}
			f.Payload = v.bytes
		case 4:
			f.Code, err = integerField(v)
		case 5:
			f.Message, err = textField(v)
		case 6:
			f.Version, err = integerField(v)
		}
		return err
	})
	if err == nil && (f.Version != 1 || f.Kind < 1 || f.Kind > 4 || f.Code > 16) {
		err = errors.New("invalid frame version, kind or result code")
	}
	return f, err
}

func decodeState(data []byte) (value State, err error) {
	err = fields(data, func(v field) (err error) {
		switch v.number {
		case 1:
			value.ID, err = textField(v)
		case 2:
			value.PID, err = integerField(v)
			if value.PID > math.MaxUint32 {
				return errors.New("pid exceeds uint32")
			}
		case 3:
			var running uint64
			running, err = integerField(v)
			value.Running = running != 0
		case 4:
			value.Status, err = textField(v)
		case 5:
			value.Bundle, err = textField(v)
		case 6:
			value.Rootfs, err = textField(v)
		case 7:
			value.Created, err = textField(v)
		case 8:
			value.Owner, err = textField(v)
		case 9:
			value.CgroupPath, err = textField(v)
		case 10:
			value.ProcessStartTime, err = integerField(v)
		}
		return err
	})
	return value, err
}

func writeFrame(w io.Writer, data []byte) error {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	for _, part := range [][]byte{header[:], data} {
		for len(part) != 0 {
			n, err := w.Write(part)
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			part = part[n:]
		}
	}
	return nil
}

func readFrame(r io.Reader) (frame, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return frame{}, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > maximumFrame {
		return frame{}, errors.New("frame length outside 1..1 MiB")
	}
	data := make([]byte, int(length))
	if _, err := io.ReadFull(r, data); err != nil {
		return frame{}, err
	}
	return decode(data)
}
