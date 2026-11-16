package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"naos.local/core/internal/container"
	"naos.local/core/internal/hawkbit"
	"naos.local/core/internal/operation"
	"naos.local/core/internal/recovery"
	"naos.local/core/internal/update"
)

func taskRequest(path, id string) string {
	body, _ := json.Marshal(map[string]string{"path": path, "request_id": id})
	return string(body)
}

func TestIntegratedTaskRequestRemainsIdempotentAfterBundleRemoval(t *testing.T) {
	path := bundle(t)
	s := services()
	var saved []update.Task
	var installs int
	s.Tasks = func() ([]update.Task, error) { return saved, nil }
	s.Update = func(context.Context, string) error { t.Fatal("persistent request used legacy installer"); return nil }
	s.InstallTask = func(_ context.Context, gotPath, id string) (update.Task, error) {
		installs++
		if gotPath != path || id != "request-1" {
			t.Fatalf("request context not passed: %q %q", gotPath, id)
		}
		task := update.Task{ID: "task-1", RequestID: id, Source: "local", Path: gotPath, State: update.Installing}
		saved = []update.Task{task}
		return task, nil
	}
	h := New(s)
	w := request(h, http.MethodPost, "/v1/update", taskRequest(path, "request-1"))
	var accepted map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &accepted); err != nil || w.Code != http.StatusAccepted || accepted["task_id"] != "task-1" || accepted["state"] != update.Installing || accepted["status"] != "accepted" || installs != 1 {
		t.Fatalf("task was not accepted: %d %s", w.Code, w.Body.String())
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	w = request(h, http.MethodPost, "/v1/update", taskRequest(path, "request-1"))
	var repeated map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &repeated); err != nil || w.Code != http.StatusAccepted || repeated["task_id"] != accepted["task_id"] || installs != 1 {
		t.Fatalf("durable request was not idempotent after removal: %d %s, installs=%d", w.Code, w.Body.String(), installs)
	}
	w = request(h, http.MethodPost, "/v1/update", taskRequest(filepath.Join(t.TempDir(), "other-missing.raucb"), "request-1"))
	if w.Code != http.StatusConflict || errorCode(t, w) != "REQUEST_CONFLICT" || installs != 1 {
		t.Fatalf("changed request identity accepted: %d %s", w.Code, w.Body.String())
	}
}

func TestIntegratedTaskIdempotencyUsesCanonicalPath(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "subdir"), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "update.raucb")
	if err := os.WriteFile(path, []byte("owned fake bundle"), 0600); err != nil {
		t.Fatal(err)
	}
	raw := root + "/subdir/../update.raucb"
	s := services()
	var saved []update.Task
	var installs int
	s.Tasks = func() ([]update.Task, error) { return saved, nil }
	s.InstallTask = func(_ context.Context, path, id string) (update.Task, error) {
		installs++
		task := update.Task{ID: "canonical-task", RequestID: id, Source: "local", Path: filepath.Clean(path), State: update.Installing}
		saved = []update.Task{task}
		return task, nil
	}
	h := New(s)
	for i := 0; i < 2; i++ {
		w := request(h, http.MethodPost, "/v1/update", taskRequest(raw, "canonical-request"))
		if w.Code != http.StatusAccepted {
			t.Fatalf("canonical request retry %d failed: %d %s", i, w.Code, w.Body.String())
		}
	}
	if installs != 1 {
		t.Fatalf("same request installed %d times", installs)
	}
}

func TestIntegratedRequestLookupErrorsAndOtherSourcesNeverInstall(t *testing.T) {
	for _, kind := range []string{"storage-error", "hawkbit-source"} {
		t.Run(kind, func(t *testing.T) {
			path := bundle(t)
			s := services()
			calls := 0
			s.InstallTask = func(context.Context, string, string) (update.Task, error) { calls++; return update.Task{}, nil }
			want, code := http.StatusConflict, "REQUEST_CONFLICT"
			if kind == "storage-error" {
				s.Tasks = func() ([]update.Task, error) { return nil, errors.New("journal unavailable") }
				want, code = http.StatusServiceUnavailable, "UPDATE_UNAVAILABLE"
			} else {
				s.Tasks = func() ([]update.Task, error) {
					return []update.Task{{ID: "external", Source: "hawkbit", Path: path, RequestID: "same-request"}}, nil
				}
			}
			w := request(New(s), http.MethodPost, "/v1/update", taskRequest(path, "same-request"))
			if w.Code != want || errorCode(t, w) != code || calls != 0 {
				t.Fatalf("unsafe fallback on lookup failure: %d %s calls=%d", w.Code, w.Body.String(), calls)
			}
		})
	}
}

func TestIntegratedInstallTaskErrorClassification(t *testing.T) {
	for _, test := range []struct {
		err    error
		status int
		code   string
	}{
		{update.ErrBusy, 409, "UPDATE_BUSY"}, {update.ErrConflict, 409, "REQUEST_CONFLICT"},
		{update.ErrInvalid, 400, "INVALID_REQUEST"}, {errors.New("journal sync failed"), 503, "UPDATE_UNAVAILABLE"},
	} {
		t.Run(test.code, func(t *testing.T) {
			s := services()
			s.InstallTask = func(context.Context, string, string) (update.Task, error) {
				return update.Task{}, fmt.Errorf("manager: %w", test.err)
			}
			w := request(New(s), http.MethodPost, "/v1/update", taskRequest(bundle(t), "request-2"))
			if w.Code != test.status || errorCode(t, w) != test.code {
				t.Fatalf("incorrect task error mapping: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestIntegratedTaskAndHawkbitSnapshots(t *testing.T) {
	s := services()
	percent := 42
	task := update.Task{ID: "saved-task", RequestID: "request-1", Source: "local", Path: "/userdata/update.raucb", State: update.InstalledPendingReboot, Version: "fixture-version"}
	s.Tasks = func() ([]update.Task, error) { return []update.Task{task}, nil }
	s.Task = func(id string) (update.Task, error) {
		if id == task.ID {
			return task, nil
		}
		return update.Task{}, update.ErrNotFound
	}
	s.HawkbitStatus = func() any {
		return hawkbit.Snapshot{Enabled: true, Heartbeat: hawkbit.HeartbeatSnapshot{HTTPStatus: 200, PollingSleep: "00:04:00"}, Updater: hawkbit.UpdaterSnapshot{Phase: "running", TaskID: "external-task", DownloadPercent: &percent}, RecentLogs: []string{"owned fixture log"}}
	}
	h := New(s)
	w := request(h, http.MethodGet, "/v1/update-tasks", "")
	var list struct {
		Tasks []update.Task `json:"tasks"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || w.Code != 200 || len(list.Tasks) != 1 || list.Tasks[0].ID != task.ID || list.Tasks[0].State != update.InstalledPendingReboot {
		t.Fatalf("task list snapshot failed: %d %s", w.Code, w.Body.String())
	}
	w = request(h, http.MethodGet, "/v1/update-tasks/saved-task", "")
	var item update.Task
	if err := json.Unmarshal(w.Body.Bytes(), &item); err != nil || w.Code != 200 || item.ID != task.ID || item.Version != task.Version {
		t.Fatalf("single task snapshot failed: %d %s", w.Code, w.Body.String())
	}
	w = request(h, http.MethodGet, "/v1/update-tasks/missing", "")
	if w.Code != 404 || errorCode(t, w) != "TASK_NOT_FOUND" {
		t.Fatalf("unknown task not reported: %d %s", w.Code, w.Body.String())
	}
	w = request(h, http.MethodGet, "/v1/hawkbit", "")
	var snapshot hawkbit.Snapshot
	if err := json.Unmarshal(w.Body.Bytes(), &snapshot); err != nil || w.Code != 200 || !snapshot.Enabled || snapshot.Heartbeat.HTTPStatus != 200 || snapshot.Updater.DownloadPercent == nil || *snapshot.Updater.DownloadPercent != 42 || len(snapshot.RecentLogs) != 1 {
		t.Fatalf("hawkbit snapshot failed: %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("status snapshot can be cached")
	}
	for _, route := range []string{"/v1/update-tasks", "/v1/update-tasks/saved-task", "/v1/hawkbit"} {
		w = request(h, http.MethodPost, route, "")
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("read-only snapshot accepted mutation: %s %d", route, w.Code)
		}
	}
}

func TestIntegratedDisabledAndMissingTaskServices(t *testing.T) {
	s := services()
	h := New(s)
	w := request(h, http.MethodGet, "/v1/hawkbit", "")
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"enabled":false,"state":"disabled"}` {
		t.Fatalf("disabled status: %d %s", w.Code, w.Body.String())
	}
	for _, route := range []string{"/v1/update-tasks", "/v1/update-tasks/a"} {
		w = request(h, http.MethodGet, route, "")
		if w.Code != 503 || errorCode(t, w) != "TASKS_UNAVAILABLE" {
			t.Fatalf("missing store pretended success: %d %s", w.Code, w.Body.String())
		}
	}
	s.Tasks = func() ([]update.Task, error) { return nil, nil }
	w = request(New(s), http.MethodGet, "/v1/update-tasks", "")
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"tasks":[]}` {
		t.Fatalf("empty tasks is not array: %d %s", w.Code, w.Body.String())
	}
}

func TestIntegratedContainerIDsAndActionsUseOnlyInjectedBackend(t *testing.T) {
	for _, action := range []string{"start", "stop", "restart"} {
		for _, id := range []string{"app1", "1", "Alpha.B_c-2", strings.Repeat("a", 128)} {
			s := services()
			calls := 0
			s.ContainerChange = func(_ context.Context, gotID, gotAction string) error {
				calls++
				if gotID != id || gotAction != action {
					t.Errorf("wrong backend request: %q %q", gotID, gotAction)
				}
				return nil
			}
			w := request(New(s), http.MethodPost, "/v1/containers/"+id+"/"+action, "")
			if w.Code != 200 || calls != 1 {
				t.Fatalf("valid container request failed: %d %s", w.Code, w.Body.String())
			}
		}
	}
	s := services()
	calls := 0
	s.ContainerChange = func(context.Context, string, string) error { calls++; return nil }
	h := New(s)
	for _, id := range []string{"bad id", "_bad", ".bad", "-bad", "业务", strings.Repeat("a", 129), "app/../../etc"} {
		w := request(h, http.MethodPost, "/v1/containers/"+url.PathEscape(id)+"/start", "")
		if w.Code != 400 || errorCode(t, w) != "INVALID_CONTAINER_ID" {
			t.Fatalf("invalid ID accepted: %q %d %s", id, w.Code, w.Body.String())
		}
	}
	for _, action := range []string{"exec", "install", "remove"} {
		w := request(h, http.MethodPost, "/v1/containers/app/"+action, "")
		if w.Code != 404 {
			t.Fatalf("unknown action accepted: %s %d", action, w.Code)
		}
	}
	w := request(h, http.MethodGet, "/v1/containers/app/start", "")
	if w.Code != 405 || calls != 0 {
		t.Fatalf("invalid control invoked backend: %d calls=%d", w.Code, calls)
	}
}

func TestIntegratedContainerRemoteCodesAndGateRelease(t *testing.T) {
	for _, test := range []struct {
		remote uint64
		status int
		code   string
	}{{3, 400, "INVALID_CONTAINER_ID"}, {5, 404, "CONTAINER_NOT_FOUND"}, {6, 409, "CONTAINER_STATE_CONFLICT"}, {9, 409, "CONTAINER_STATE_CONFLICT"}, {12, 503, "CONTAINERS_UNAVAILABLE"}} {
		t.Run(fmt.Sprint(test.remote), func(t *testing.T) {
			gate := operation.New()
			s := services()
			s.Gate = gate
			s.ContainerChange = func(context.Context, string, string) error {
				return fmt.Errorf("fixture adapter: %w", &container.RemoteError{Code: test.remote, Message: "owned fixture error"})
			}
			w := request(New(s), http.MethodPost, "/v1/containers/app/start", "")
			if w.Code != test.status || errorCode(t, w) != test.code || gate.Busy() {
				t.Fatalf("remote mapping leaked lease or status: %d %s busy=%v", w.Code, w.Body.String(), gate.Busy())
			}
		})
	}
}

func TestIntegratedExternalGateBlocksAllMutationsBeforeCallbacks(t *testing.T) {
	gate := operation.New()
	external, err := gate.TryAcquire("hawkbit-update")
	if err != nil {
		t.Fatal(err)
	}
	defer external.Release()
	s := services()
	s.Gate = gate
	var calls atomic.Int32
	s.Busy = func(context.Context) (bool, error) { calls.Add(1); return false, nil }
	s.Recovery = func(context.Context) error { calls.Add(1); return nil }
	s.Reboot = func() error { calls.Add(1); return nil }
	s.ContainerChange = func(context.Context, string, string) error { calls.Add(1); return nil }
	h := New(s)
	for _, route := range []string{"/v1/reboot", "/v1/recovery", "/v1/containers/app/start", "/v1/containers/app/stop", "/v1/containers/app/restart"} {
		w := request(h, http.MethodPost, route, "")
		if w.Code != 409 || errorCode(t, w) != "UPDATE_BUSY" || calls.Load() != 0 || gate.Kind() != "hawkbit-update" {
			t.Fatalf("external lease was bypassed: %s %d %s calls=%d", route, w.Code, w.Body.String(), calls.Load())
		}
	}
	w := request(h, http.MethodGet, "/v1/containers", "")
	if w.Code != 200 {
		t.Fatal("external update blocked read-only container list")
	}
	external.Release()
	w = request(h, http.MethodPost, "/v1/containers/app/stop", "")
	if w.Code != 200 || calls.Load() != 1 || gate.Busy() {
		t.Fatalf("released operation remained blocked: %d %s", w.Code, w.Body.String())
	}
}

func TestIntegratedFailedOrdinaryRebootReleasesLeaseAndAdmission(t *testing.T) {
	gate := operation.New()
	s := services()
	s.Gate = gate
	called := make(chan struct{}, 1)
	s.Reboot = func() error { called <- struct{}{}; return errors.New("fixture reboot failed") }
	s.ContainerChange = func(context.Context, string, string) error { return nil }
	h := New(s)
	w := request(h, http.MethodPost, "/v1/reboot", "")
	if w.Code != 202 || !gate.Busy() {
		t.Fatalf("accepted reboot did not retain gate: %d %s", w.Code, w.Body.String())
	}
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("accepted reboot callback not invoked")
	}
	deadline := time.Now().Add(time.Second)
	for gate.Busy() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if gate.Busy() {
		t.Fatal("failed ordinary reboot leaked operation lease")
	}
	w = request(h, http.MethodPost, "/v1/containers/app/start", "")
	if w.Code != 200 {
		t.Fatalf("failed ordinary reboot left admission closed: %d %s", w.Code, w.Body.String())
	}
}

func TestIntegratedRecoveryFailuresRetainOnlyUncertainLease(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(fmt.Sprint(uncertain), func(t *testing.T) {
			gate := operation.New()
			s := services()
			s.Gate = gate
			var reboots, changes atomic.Int32
			s.Recovery = func(context.Context) error {
				if uncertain {
					return fmt.Errorf("fixture recovery write: %w", recovery.ErrUncertain)
				}
				return errors.New("fixture pre-write validation failed")
			}
			s.Reboot = func() error { reboots.Add(1); return nil }
			s.ContainerChange = func(context.Context, string, string) error { changes.Add(1); return nil }
			h := New(s)
			w := request(h, http.MethodPost, "/v1/recovery", "")
			if w.Code != 503 || errorCode(t, w) != "RECOVERY_FAILED" || gate.Busy() != uncertain || reboots.Load() != 0 {
				t.Fatalf("incorrect recovery failure ownership: %d %s busy=%v", w.Code, w.Body.String(), gate.Busy())
			}
			w = request(h, http.MethodPost, "/v1/containers/app/start", "")
			if uncertain {
				if w.Code != 409 || errorCode(t, w) != "REBOOT_PENDING" || changes.Load() != 0 {
					t.Fatal("uncertain recovery allowed a competing action")
				}
			} else if w.Code != 200 || changes.Load() != 1 || gate.Busy() {
				t.Fatal("clean recovery rejection leaked admission")
			}
		})
	}
}

func TestIntegratedDurableRecoveryRetainsLeaseWhenRebootFails(t *testing.T) {
	gate := operation.New()
	s := services()
	s.Gate = gate
	called := make(chan struct{}, 1)
	s.Recovery = func(context.Context) error { return nil }
	s.Reboot = func() error { called <- struct{}{}; return errors.New("fixture reboot failed") }
	s.ContainerChange = func(context.Context, string, string) error {
		t.Fatal("container control ran after durable recovery")
		return nil
	}
	h := New(s)
	w := request(h, http.MethodPost, "/v1/recovery", "")
	if w.Code != 202 {
		t.Fatalf("recovery not accepted: %d %s", w.Code, w.Body.String())
	}
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("recovery reboot callback missing")
	}
	for _, route := range []string{"/v1/reboot", "/v1/recovery", "/v1/containers/app/start"} {
		w = request(h, http.MethodPost, route, "")
		if w.Code != 409 || errorCode(t, w) != "REBOOT_PENDING" || gate.Kind() != "recovery" {
			t.Fatalf("durable recovery lost exclusion after reboot failure: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestIntegratedNaosdCgroupPreparationIsIdempotent(t *testing.T) {
	// Run a private copy of the real script. All filesystem paths point at
	// owned fixtures; mount writes a fake /proc/mounts instead of mounting.
	script, err := os.ReadFile("../../init.d/naosd")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, filesystem                     string
		mounted, missingDirectory, failMount bool
		wantMounts                           int
		wantFailure                          bool
	}{
		{"first-start", "", false, false, false, 1, false},
		{"already-mounted", "cgroup2", true, false, false, 0, false},
		{"wrong-filesystem", "tmpfs", true, false, false, 0, true},
		{"mount-failure", "", false, false, true, 1, true},
		{"missing-cgroup-directory", "", false, true, false, 1, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			trace := filepath.Join(root, "commands.log")
			mountsPath := filepath.Join(root, "proc-mounts")
			cgroup := filepath.Join(root, "sys/fs/cgroup")
			for _, path := range []string{filepath.Dir(cgroup), filepath.Join(root, "run/naos"), filepath.Join(root, "var/lib"), filepath.Join(root, "etc/naosd")} {
				if err := os.MkdirAll(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if !test.missingDirectory {
				// sysfs exists with 0555; an owner on a normal host could chmod it,
				// so checkpath/chmod mocks explicitly reject that kernel operation.
				if err := os.Mkdir(cgroup, 0555); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(root, "etc/naosd/config.yml"), []byte("owned test configuration\n"), 0600); err != nil {
				t.Fatal(err)
			}
			mountsText := "rootfs / rootfs rw 0 0\n"
			if test.mounted {
				mountsText += "cgroup2 " + cgroup + " " + test.filesystem + " rw 0 0\n"
			}
			if err := os.WriteFile(mountsPath, []byte(mountsText), 0600); err != nil {
				t.Fatal(err)
			}
			// awk itself stays real, including the script's fstype predicate.
			fixture := strings.NewReplacer(
				"/proc/mounts", mountsPath, "/sys/fs/cgroup", cgroup,
				"/run/naos/container", filepath.Join(root, "run/naos/container"),
				"/run/naos/netns", filepath.Join(root, "run/naos/netns"),
				"/var/lib/naos", filepath.Join(root, "var/lib/naos"),
				"/etc/naosd/config.yml", filepath.Join(root, "etc/naosd/config.yml"),
			).Replace(string(script))
			fixturePath := filepath.Join(root, "naosd-script")
			if err := os.WriteFile(fixturePath, []byte(fixture), 0600); err != nil {
				t.Fatal(err)
			}
			body := `
mountpoint() {
    [ "$1" = -q ] && [ "$2" = "$CGROUP" ] || return 2
    awk -v point="$2" '$2 == point { found=1 } END { exit !found }' "$MOUNTS"
}
stat() { printf 'forbidden-stat\n' >>"$TRACE"; return 1; }
chmod() {
    for path do [ "$path" != "$CGROUP" ] || { printf 'forbidden-cgroup-chmod\n' >>"$TRACE"; return 1; }; done
    command chmod "$@"
}
checkpath() {
    printf 'checkpath %s\n' "$*" >>"$TRACE"
    [ "$1" = -d ] && [ "$2" = -m ] || return 2
    mode=$3
    shift 3
    for path do
        [ "$path" != "$CGROUP" ] || { printf 'forbidden-cgroup-checkpath\n' >>"$TRACE"; return 1; }
        # Real checkpath does not create absent parent directories.
        [ -d "${path%/*}" ] || { printf 'missing-parent %s\n' "$path" >>"$TRACE"; return 1; }
        if [ -d "$path" ]; then chmod "$mode" "$path" || return 1
        else command mkdir -m "$mode" "$path" || return 1; fi
    done
}
mount() {
    printf 'mount %s\n' "$*" >>"$TRACE"
    [ "$*" = "-t cgroup2 -o nosuid,nodev,noexec cgroup2 $CGROUP" ] || return 2
    [ "$FAIL_MOUNT" = false ] || return 1
    [ -d "$CGROUP" ] || return 1
    printf 'cgroup2 %s cgroup2 rw,nosuid,nodev,noexec 0 0\n' "$CGROUP" >>"$MOUNTS"
}
eerror() { printf 'error %s\n' "$*" >>"$TRACE"; }
. "$1"
start_pre || exit 17
start_pre || exit 18
`
			cmd := exec.Command("sh", "-c", body, "naosd-service-test", fixturePath)
			cmd.Env = append(os.Environ(), "TRACE="+trace, "CGROUP="+cgroup, "MOUNTS="+mountsPath, "FAIL_MOUNT="+fmt.Sprint(test.failMount))
			output, err := cmd.CombinedOutput()
			if (err != nil) != test.wantFailure {
				t.Fatalf("service fixture status: %v %s", err, output)
			}
			data, readErr := os.ReadFile(trace)
			if readErr != nil {
				t.Fatal(readErr)
			}
			mounts := strings.Count(string(data), "mount -t cgroup2 -o nosuid,nodev,noexec cgroup2 "+cgroup+"\n")
			if mounts != test.wantMounts {
				t.Fatalf("cgroup preparation mounted %d times, want %d: %s", mounts, test.wantMounts, data)
			}
			if strings.Contains(string(data), "forbidden-") || strings.Contains(string(data), "missing-parent") {
				t.Fatalf("service used unsupported sysfs/stat/checkpath behavior: %s", data)
			}
			if !test.missingDirectory {
				info, err := os.Stat(cgroup)
				if err != nil || info.Mode().Perm() != 0555 {
					t.Fatalf("service modified existing sysfs permissions: %v %v", info, err)
				}
			}
			if !test.wantFailure {
				for path, mode := range map[string]os.FileMode{"run/naos/container": 0700, "run/naos/netns": 0700, "var/lib/naos": 0755, "var/lib/naos/containers": 0755} {
					info, err := os.Stat(filepath.Join(root, path))
					if err != nil || !info.IsDir() || info.Mode().Perm() != mode {
						t.Fatalf("service did not prepare %s: %v %v", path, info, err)
					}
				}
				data, err := os.ReadFile(mountsPath)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(data), " "+cgroup+" cgroup2 ") {
					t.Fatal("second start did not use the fake mounted cgroup2")
				}
			}
		})
	}
	data, err := os.ReadFile("../../config/naosd.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "  autorunAll: true\n") {
		t.Fatal("default daemon configuration changed the existing business autorun policy")
	}
}
