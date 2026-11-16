package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"gopkg.in/ini.v1"
)

// readINIFile uses the library's normal last-key-wins rules. Its errors are
// redacted because syntax errors from the library can contain credential lines.
func readINIFile(path string) (*ini.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	var data []byte
	if err == nil {
		defer f.Close()
		info, statErr := f.Stat()
		if statErr != nil {
			return nil, fmt.Errorf("inspect Core configuration: %w", statErr)
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("Core configuration must be an ordinary file")
		}
		data, err = io.ReadAll(io.LimitReader(f, maximumConfigBytes+1))
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read Core configuration: %w", err)
	}
	if len(data) > maximumConfigBytes {
		return nil, errors.New("Core configuration exceeds 64 KiB")
	}
	file, err := ini.LoadSources(ini.LoadOptions{SpaceBeforeInlineComment: true}, data)
	if err != nil {
		return nil, errors.New("invalid Core configuration INI syntax")
	}
	return file, nil
}

// EnsureControllerID generates only when the same locked INI has no valid ID.
// Identity and registration share this directory lock and atomic writer.
func EnsureControllerID(path string, generate func() (string, error)) (string, error) {
	var id string
	err := editINIFile(path, func(file *ini.File) (bool, error) {
		cfg := configurationFromINI(defaults(), path, file)
		id = cfg.Hawkbit.ControllerID
		if id != "" {
			return false, nil
		}
		var err error
		id, err = generate()
		if err != nil {
			return false, err
		}
		if id == "" || !identifier(id, 128) {
			return false, errors.New("invalid generated controller identity")
		}
		file.Section("hawkbit").Key("controller_id").SetValue(id)
		return true, nil
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

func editINIFile(path string, edit func(*ini.File) (bool, error)) error {
	if path == "" || strings.ContainsRune(path, 0) {
		return errors.New("Core configuration path is required")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve Core configuration path: %w", err)
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return fmt.Errorf("create Core configuration directory: %w", err)
	}
	directory, err := os.Open(parent)
	if err != nil {
		return fmt.Errorf("open Core configuration directory: %w", err)
	}
	defer directory.Close()
	if err := syscall.Flock(int(directory.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock Core configuration directory: %w", err)
	}
	defer syscall.Flock(int(directory.Fd()), syscall.LOCK_UN)
	file, err := readINIFile(path)
	if err != nil {
		return err
	}
	changed, err := edit(file)
	if err != nil || !changed {
		return err
	}
	var data bytes.Buffer
	if _, err := file.WriteTo(&data); err != nil {
		return errors.New("cannot serialize Core configuration INI")
	}
	if data.Len() > maximumConfigBytes {
		return errors.New("updated Core configuration exceeds 64 KiB")
	}
	return saveINIFile(path, data.Bytes(), directory)
}

func saveINIFile(path string, data []byte, directory *os.File) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".device.ini-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err = errors.Join(err, closeErr); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	return directory.Sync()
}
