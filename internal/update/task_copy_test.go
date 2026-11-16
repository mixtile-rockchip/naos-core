package update

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

// The previous implementation is a wire-format oracle, not production code.
func previousJSONTaskClone(t Task) Task {
	data, _ := json.Marshal(t)
	var out Task
	_ = json.Unmarshal(data, &out)
	return out
}

func taskCopyFixture() Task {
	result, exit := int32(0), 0
	now := time.Date(2026, time.November, 3, 10, 12, 13, 123456789, time.UTC)
	slots := make([]SlotEvidence, 4)
	for i := range slots {
		slots[i] = SlotEvidence{Name: fmt.Sprintf("slot.%d", i), Class: "rootfs", Parent: "parent", Device: fmt.Sprintf("/dev/slot%d", i), Bootname: "A", State: "inactive", BootStatus: "good", Version: "版本-1", ManifestHash: "manifest", SHA256: "sha256", Status: "ok", Transaction: "transaction", InstalledAt: "2026-11-03T10:12:13Z", InstalledCount: 7}
	}
	return Task{ID: "copy-task", RequestID: "request-1", Source: "hawkbit", Path: "/userdata/update.raucb", ActionID: "action-1", State: RunningExternal, CreatedAt: now, UpdatedAt: now.Add(time.Second), Version: "release-1", ManifestHash: "manifest", Images: map[string]string{"boot": "boot-hash", "rootfs": "root-hash"}, BootID: "boot-1", TargetSlot: "slot.1", TargetBootname: "B", BootSlot: "slot.0", Primary: "slot.1", Progress: Progress{Percentage: 25, Message: "中文 <progress>\n\t\"quoted\"", Depth: 2}, Result: &result, UpdaterExit: &exit, Error: "line one\nline two", ExternalIdentity: &ExternalIdentity{PID: 123, StartTime: 456, BootID: "boot-1", Exe: "/usr/bin/rauc-hawkbit-updater", ConfigPath: "/run/naos/core/hawkbit.conf", ConfigSHA256: "config-hash"}, Before: slots, Installed: append([]SlotEvidence(nil), slots[2:]...), ObservedInstalling: true}
}

func taskWireValue(t *testing.T, task Task) any {
	t.Helper()
	data, err := json.Marshal(task)
	if err != nil {
		t.Fatalf("encode task: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode task: %v", err)
	}
	return value
}

func TestTaskCopyWireCompatibility(t *testing.T) {
	full := taskCopyFixture()
	cases := map[string]Task{"full": full, "zero": {}, "monotonic-time": {CreatedAt: time.Now(), UpdatedAt: time.Now()}}
	empty := full
	empty.Images = map[string]string{}
	empty.Before = make([]SlotEvidence, 0, 4)
	empty.Installed = []SlotEvidence{}
	cases["empty-collections"] = empty
	nils := full
	nils.Images = nil
	nils.Before = nil
	nils.Installed = nil
	nils.Result = nil
	nils.UpdaterExit = nil
	nils.ExternalIdentity = nil
	cases["nil-collections-and-pointers"] = nils
	for name, offset := range map[string]int{"east-half-hour": 5*3600 + 30*60, "west": -7 * 3600, "named-zero": 0} {
		sample := full
		sample.CreatedAt = time.Date(2020, time.February, 29, 23, 59, 59, 987654321, time.FixedZone(name, offset))
		sample.UpdatedAt = sample.CreatedAt.Add(2 * time.Second)
		cases[name] = sample
	}
	invalid := taskCopyFixture()
	invalid.Error = "invalid-\xff\xfe"
	invalid.Progress.Message = "nul\x00newline\n\xff"
	invalid.Images = map[string]string{"bad-\xff": "value-\xfe", "bad-\xfe": "second"}
	cases["invalid-utf8-wire-semantics"] = invalid
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			got := cloneTask(input)
			previous := previousJSONTaskClone(input)
			if !reflect.DeepEqual(taskWireValue(t, got), taskWireValue(t, previous)) {
				t.Fatal("typed clone changed JSON task semantics")
			}
			if got.CreatedAt != got.CreatedAt.Round(0) || got.UpdatedAt != got.UpdatedAt.Round(0) {
				t.Fatal("clone retained a monotonic clock reading")
			}
		})
	}
	got := cloneTask(empty)
	if got.Images != nil || got.Installed != nil || got.Before == nil {
		t.Fatal("omitempty / Before nil distinctions changed")
	}
}

func TestTaskCopyReferenceIsolation(t *testing.T) {
	input := taskCopyFixture()
	before, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	out := cloneTask(input)
	out.Images["boot"] = "changed"
	out.Images["new"] = "new"
	*out.Result = 9
	*out.UpdaterExit = 11
	out.ExternalIdentity.PID = 999
	out.ExternalIdentity.ConfigPath = "changed"
	out.Before[0].Name = "changed-before"
	out.Installed[0].SHA256 = "changed-installed"
	after, err := json.Marshal(input)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("modifying clone changed original reference fields")
	}
	// Also prove that subsequent changes in the source cannot mutate a clone.
	out = cloneTask(input)
	snapshot, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	input.Images["boot"] = "source-changed"
	*input.Result = 19
	*input.UpdaterExit = 21
	input.ExternalIdentity.BootID = "source-changed"
	input.Before[0].Name = "source-changed"
	input.Installed[0].SHA256 = "source-changed"
	after, err = json.Marshal(out)
	if err != nil || !bytes.Equal(snapshot, after) {
		t.Fatal("modifying original changed clone reference fields")
	}
}

func TestTaskCopyNoopHistoryDoesNotWrite(t *testing.T) {
	original := taskCopyFixture()
	previousError := errors.New("keep prior persistence error")
	c := New()
	c.persistent = &tracker{tasks: []Task{original}, saveError: previousError}
	first := &c.persistent.tasks[0]
	// A nil store would panic if this unchanged observation attempted a write.
	if err := c.commitHistory(original); err != nil {
		t.Fatal(err)
	}
	if len(c.persistent.tasks) != 1 || &c.persistent.tasks[0] != first || c.persistent.saveError != previousError {
		t.Fatal("no-op history changed records or persistence state")
	}
}

var taskCopySink Task
var taskCopyError error

func BenchmarkTaskCopyClone(b *testing.B) {
	sample := taskCopyFixture()
	for _, variant := range []struct {
		name  string
		clone func(Task) Task
	}{{"previous_json", previousJSONTaskClone}, {"typed", cloneTask}} {
		b.Run(variant.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				taskCopySink = variant.clone(sample)
			}
		})
	}
}

// This is the exact previous no-op branch: array allocation/copy happened
// before sameTask. It deliberately never writes a journal or touches D-Bus.
func previousNoopHistory(c *Client, task Task) error {
	next := make([]Task, len(c.persistent.tasks))
	copy(next, c.persistent.tasks)
	for _, old := range next {
		if old.ID == task.ID && sameTask(old, task) {
			return nil
		}
	}
	return errors.New("benchmark expected unchanged existing task")
}

func BenchmarkTaskCopyNoopHistory(b *testing.B) {
	sample := taskCopyFixture()
	c := New()
	c.persistent = &tracker{tasks: make([]Task, 32)}
	for i := range c.persistent.tasks {
		c.persistent.tasks[i] = sample
		c.persistent.tasks[i].ID = fmt.Sprintf("task-%d", i)
	}
	sample = c.persistent.tasks[31]
	for _, variant := range []struct {
		name   string
		commit func(*Client, Task) error
	}{{"previous_array_first", previousNoopHistory}, {"delayed_array", func(c *Client, t Task) error { return c.commitHistory(t) }}} {
		b.Run(variant.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				taskCopyError = variant.commit(c, sample)
			}
		})
	}
}
