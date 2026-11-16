package oem

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestUnsupportedDoesNotOpenOTP(t *testing.T) {
	for _, soc := range []string{"", "rk3568", "RK3588"} {
		info, err := read(soc, func() (io.ReadCloser, error) {
			t.Fatal("unsupported platform opened OTP")
			return nil, nil
		})
		if !errors.Is(err, ErrUnsupported) || info != (Info{}) {
			t.Fatalf("soc=%q info=%v err=%v", soc, info, err)
		}
	}
}

func TestReadLayoutAndDoesNotOverread(t *testing.T) {
	sn := "1234567890ABCDEF"
	mac := [6]byte{0x02, 0x11, 0x22, 0xaa, 0xbb, 0xcc}
	data := append([]byte(sn), mac[:]...)
	data = append(data, 0xab, 0xcd) // Padding is not part of the MAC.
	tail := []byte("unrelated OTP bytes")
	reader := bytes.NewBuffer(append(data, tail...))
	info, err := read("rk3588", func() (io.ReadCloser, error) {
		return io.NopCloser(reader), nil
	})
	if err != nil || string(info.SN[:]) != sn || info.MAC != mac {
		t.Fatalf("info=%v err=%v", info, err)
	}
	if !bytes.Equal(reader.Bytes(), tail) {
		t.Fatal("read extended beyond the first 24 bytes")
	}
}

func TestShortReadIsRejected(t *testing.T) {
	for _, n := range []int{0, 15, 16, 22, 23} {
		info, err := read("rk3588", func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(make([]byte, n))), nil
		})
		if err == nil || info != (Info{}) {
			t.Fatalf("length=%d info=%v err=%v", n, info, err)
		}
	}
}

func TestOpenErrorIsReturned(t *testing.T) {
	want := errors.New("OTP is unavailable")
	_, err := read("rk3588", func() (io.ReadCloser, error) { return nil, want })
	if !errors.Is(err, want) {
		t.Fatalf("open error lost: %v", err)
	}
}
