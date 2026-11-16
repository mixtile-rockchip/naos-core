// Package oem reads the fixed OEM identity layout from RK3588 OTP.
package oem

import (
	"errors"
	"fmt"
	"io"
	"os"
)

var ErrUnsupported = errors.New("OEM is not supported on this platform")

type Info struct {
	SN  [16]byte
	MAC [6]byte
}

func (i Info) Strings() (string, string) {
	sn := i.SN
	for n, b := range sn {
		if b < 0x20 || b > 0x7e {
			sn[n] = '.'
		}
	}
	return string(sn[:]), fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
		i.MAC[0], i.MAC[1], i.MAC[2], i.MAC[3], i.MAC[4], i.MAC[5])
}

func Read(soc string) (Info, error) {
	return read(soc, func() (io.ReadCloser, error) {
		return os.Open("/sys/bus/nvmem/devices/rockchip-secure-otp0/nvmem")
	})
}

func read(soc string, open func() (io.ReadCloser, error)) (Info, error) {
	var info Info
	if soc != "rk3588" {
		return info, ErrUnsupported
	}
	f, err := open()
	if err != nil {
		return info, err
	}
	defer f.Close()

	// Offset 0 and length 24 satisfy the nvmem driver's 4-byte alignment.
	var data [24]byte
	if _, err := io.ReadFull(f, data[:]); err != nil {
		return info, err
	}
	copy(info.SN[:], data[:16])
	copy(info.MAC[:], data[16:22])
	return info, nil
}
