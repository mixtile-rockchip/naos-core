package update

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrNotFound    = os.ErrNotExist
	ErrConflict    = errors.New("request_id was used for a different update")
	ErrInvalid     = errors.New("invalid update request")
	ErrPersistence = errors.New("cannot durably save update task")
)

var ErrTaskNotFound = ErrNotFound
var ErrRequestConflict = ErrConflict

const (
	Submitted              = "submitted"
	Installing             = "installing"
	RunningExternal        = "running_external"
	InstalledPendingReboot = "installed_pending_reboot"
	BootConfirmed          = "boot_confirmed"
	Failed                 = "failed"
	Unknown                = "unknown"
)

type ExternalIdentity struct {
	PID          int    `json:"pid"`
	StartTime    uint64 `json:"start_time"`
	BootID       string `json:"boot_id"`
	Exe          string `json:"exe"`
	ConfigPath   string `json:"config_path"`
	ConfigSHA256 string `json:"config_sha256"`
}

type ExternalRequest struct{ Source, RequestID, Path, Version, ActionID string }

type SlotEvidence struct {
	Name           string `json:"name"`
	Class          string `json:"class"`
	Parent         string `json:"parent,omitempty"`
	Device         string `json:"device,omitempty"`
	Bootname       string `json:"bootname,omitempty"`
	State          string `json:"state,omitempty"`
	BootStatus     string `json:"boot_status,omitempty"`
	Version        string `json:"version,omitempty"`
	ManifestHash   string `json:"manifest_hash,omitempty"`
	SHA256         string `json:"sha256,omitempty"`
	Status         string `json:"status,omitempty"`
	Transaction    string `json:"transaction,omitempty"`
	InstalledAt    string `json:"installed_at,omitempty"`
	InstalledCount uint32 `json:"installed_count,omitempty"`
}

type Task struct {
	ID                 string            `json:"id"`
	RequestID          string            `json:"request_id,omitempty"`
	Source             string            `json:"source"`
	Path               string            `json:"path,omitempty"`
	ActionID           string            `json:"action_id,omitempty"`
	State              string            `json:"state"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
	Version            string            `json:"version,omitempty"`
	ManifestHash       string            `json:"manifest_hash,omitempty"`
	Images             map[string]string `json:"images,omitempty"`
	BootID             string            `json:"boot_id"`
	TargetSlot         string            `json:"target_slot"`
	TargetBootname     string            `json:"target_bootname"`
	BootSlot           string            `json:"boot_slot,omitempty"`
	Primary            string            `json:"primary,omitempty"`
	Progress           Progress          `json:"progress"`
	Result             *int32            `json:"result"`
	UpdaterExit        *int              `json:"updater_exit,omitempty"`
	Error              string            `json:"error,omitempty"`
	ExternalIdentity   *ExternalIdentity `json:"external_identity,omitempty"`
	Before             []SlotEvidence    `json:"before"`
	Installed          []SlotEvidence    `json:"installed,omitempty"`
	ObservedInstalling bool              `json:"observed_installing,omitempty"`
}

type journal struct {
	Format int    `json:"format"`
	Tasks  []Task `json:"tasks"`
}
type taskStore struct {
	dir           string
	removePending func(string) error
	syncDirectory func() error
}

const maxTasks = 32
const maxJournal = 1024 * 1024

func openStore(dir string) (*taskStore, []Task, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) == "/" {
		return nil, nil, fmt.Errorf("%w: state directory must be absolute", ErrInvalid)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return nil, nil, err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("update state directory is not a directory")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, nil, err
	}
	s := &taskStore{dir: dir}
	tasks, err := s.read("tasks.json", maxTasks)
	return s, tasks, err
}

func (s *taskStore) read(name string, maximum int) ([]Task, error) {
	path := filepath.Join(s.dir, name)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > maxJournal {
		return nil, errors.New("update journal must be bounded regular mode 0600")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, maxJournal+1))
	dec.DisallowUnknownFields()
	var j journal
	if err := dec.Decode(&j); err != nil {
		return nil, fmt.Errorf("read update journal: %w", err)
	}
	if dec.Decode(new(any)) != io.EOF || j.Format != 1 || len(j.Tasks) > maximum {
		return nil, errors.New("invalid update journal format")
	}
	ids := map[string]bool{}
	requests := map[string]bool{}
	for _, t := range j.Tasks {
		if !validID(t.ID) || ids[t.ID] || t.CreatedAt.IsZero() || t.UpdatedAt.IsZero() || !validState(t.State) || (t.Source != "local" && t.Source != "hawkbit") {
			return nil, errors.New("invalid update task record")
		}
		ids[t.ID] = true
		if t.RequestID != "" {
			if requests[t.RequestID] {
				return nil, errors.New("duplicate request_id in update journal")
			}
			requests[t.RequestID] = true
		}
	}
	return j.Tasks, nil
}
func validID(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._:-", r)) {
			return false
		}
	}
	return true
}
func validState(s string) bool {
	switch s {
	case Submitted, Installing, RunningExternal, InstalledPendingReboot, BootConfirmed, Failed, Unknown:
		return true
	}
	return false
}
func taskID() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
func cloneTask(t Task) Task {
	out := t
	// Task timestamps are UTC in normal operation. JSON round trips remove
	// monotonic readings; keep that property without serializing the task.
	out.CreatedAt = t.CreatedAt.Round(0)
	out.UpdatedAt = t.UpdatedAt.Round(0)
	if len(t.Images) == 0 {
		out.Images = nil // The previous JSON clone omitted an empty map.
	} else {
		out.Images = make(map[string]string, len(t.Images))
		for key, value := range t.Images {
			out.Images[key] = value
		}
	}
	if t.Result != nil {
		value := *t.Result
		out.Result = &value
	}
	if t.UpdaterExit != nil {
		value := *t.UpdaterExit
		out.UpdaterExit = &value
	}
	if t.ExternalIdentity != nil {
		value := *t.ExternalIdentity
		out.ExternalIdentity = &value
	}
	if t.Before != nil {
		out.Before = make([]SlotEvidence, len(t.Before))
		copy(out.Before, t.Before)
	}
	if len(t.Installed) == 0 {
		out.Installed = nil // This slice has omitempty; Before does not.
	} else {
		out.Installed = make([]SlotEvidence, len(t.Installed))
		copy(out.Installed, t.Installed)
	}
	return out
}
func (s *taskStore) save(tasks []Task) error {
	return s.saveFile("tasks.json", tasks, maxTasks)
}

func (s *taskStore) saveFile(filename string, tasks []Task, maximum int) error {
	if len(tasks) > maximum {
		return errors.New("update journal exceeds task bound")
	}
	data, err := json.MarshalIndent(journal{Format: 1, Tasks: tasks}, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > maxJournal {
		return errors.New("update journal exceeds bound")
	}
	data = append(data, '\n')
	f, err := os.CreateTemp(s.dir, ".tasks-*")
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
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, filepath.Join(s.dir, filename)); err != nil {
		return err
	}
	return s.syncDir()
}

func (s *taskStore) syncDir() error {
	if s.syncDirectory != nil {
		return s.syncDirectory()
	}
	d, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func sameTask(a, b Task) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
