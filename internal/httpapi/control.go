package httpapi

import (
	"errors"
	"net/http"

	"naos.local/core/internal/container"
	"naos.local/core/internal/update"
)

func updateFailure(w http.ResponseWriter, err error) {
	status, code := http.StatusServiceUnavailable, "UPDATE_UNAVAILABLE"
	switch {
	case errors.Is(err, update.ErrBusy):
		status, code = http.StatusConflict, "UPDATE_BUSY"
	case errors.Is(err, update.ErrConflict):
		status, code = http.StatusConflict, "REQUEST_CONFLICT"
	case errors.Is(err, update.ErrNotFound):
		status, code = http.StatusNotFound, "TASK_NOT_FOUND"
	case errors.Is(err, update.ErrInvalid):
		status, code = http.StatusBadRequest, "INVALID_REQUEST"
	}
	failure(w, status, code, err.Error())
}

func (a *api) tasks(w http.ResponseWriter, r *http.Request) {
	if a.services.Tasks == nil {
		failure(w, http.StatusServiceUnavailable, "TASKS_UNAVAILABLE", "update task storage is not configured")
		return
	}
	tasks, err := a.services.Tasks()
	if err != nil {
		updateFailure(w, err)
		return
	}
	if tasks == nil {
		tasks = []update.Task{}
	}
	respond(w, http.StatusOK, map[string]any{"tasks": tasks})
}

func (a *api) task(w http.ResponseWriter, r *http.Request) {
	if a.services.Task == nil {
		failure(w, http.StatusServiceUnavailable, "TASKS_UNAVAILABLE", "update task storage is not configured")
		return
	}
	task, err := a.services.Task(r.PathValue("id"))
	if err != nil {
		updateFailure(w, err)
		return
	}
	respond(w, http.StatusOK, task)
}

func (a *api) hawkbit(w http.ResponseWriter, r *http.Request) {
	if a.services.HawkbitStatus == nil {
		respond(w, http.StatusOK, map[string]any{"enabled": false, "state": "disabled"})
		return
	}
	respond(w, http.StatusOK, a.services.HawkbitStatus())
}

func (a *api) changeContainer(w http.ResponseWriter, r *http.Request) {
	id, action := r.PathValue("id"), r.PathValue("action")
	if action != "start" && action != "stop" && action != "restart" {
		failure(w, http.StatusNotFound, "NOT_FOUND", "unknown container operation")
		return
	}
	if !container.ValidID(id) {
		failure(w, http.StatusBadRequest, "INVALID_CONTAINER_ID", container.ErrInvalidID.Error())
		return
	}
	if a.services.ContainerChange == nil {
		failure(w, http.StatusServiceUnavailable, "CONTAINERS_UNAVAILABLE", "container control is not configured")
		return
	}
	a.actions.Lock()
	defer a.actions.Unlock()
	if a.rebooting {
		failure(w, http.StatusConflict, "REBOOT_PENDING", "device reboot is pending")
		return
	}
	if a.services.Gate != nil {
		lease, err := a.services.Gate.TryAcquire("container-" + action)
		if err != nil {
			failure(w, http.StatusConflict, "UPDATE_BUSY", "another device operation is active")
			return
		}
		defer lease.Release()
	}
	if err := a.services.ContainerChange(r.Context(), id, action); err != nil {
		status, code := http.StatusServiceUnavailable, "CONTAINERS_UNAVAILABLE"
		var remote *container.RemoteError
		if errors.As(err, &remote) {
			switch remote.Code {
			case 3:
				status, code = http.StatusBadRequest, "INVALID_CONTAINER_ID"
			case 5:
				status, code = http.StatusNotFound, "CONTAINER_NOT_FOUND"
			case 6, 9:
				status, code = http.StatusConflict, "CONTAINER_STATE_CONFLICT"
			}
		}
		failure(w, status, code, err.Error())
		return
	}
	respond(w, http.StatusOK, map[string]string{"status": "ok", "id": id, "action": action})
}
