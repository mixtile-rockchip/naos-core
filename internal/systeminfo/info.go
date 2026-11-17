// Package systeminfo reads the running NAOS firmware metadata.
package systeminfo

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
)

const maxMetadataSize = 64 * 1024

type Info struct {
	Version string `json:"version"`
	BuildID string `json:"build_id"`
	Machine string `json:"machine"`
}

func Read() (Info, error) {
	return read("/usr/lib/naos/version.json")
}

func read(path string) (Info, error) {
	f, err := os.Open(path)
	if err != nil {
		return Info{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxMetadataSize+1))
	if err != nil {
		return Info{}, err
	}
	var info Info
	if len(data) > maxMetadataSize || json.Unmarshal(data, &info) != nil {
		return Info{}, errors.New("invalid system version metadata")
	}
	info.Version = strings.TrimSpace(info.Version)
	info.BuildID = strings.TrimSpace(info.BuildID)
	info.Machine = strings.TrimSpace(info.Machine)
	if info.Version == "" {
		return Info{}, errors.New("system version is unavailable")
	}
	return info, nil
}
