package hawkbit

import (
	"context"

	"naos.local/core/internal/config"
)

type RegisterResult struct {
	Registered   bool   `json:"registered"`
	HTTPStatus   int    `json:"http_status"`
	ServerURL    string `json:"server_url,omitempty"`
	ControllerID string `json:"controller_id,omitempty"`
	PollingSleep string `json:"polling_sleep,omitempty"`
	Error        string `json:"error,omitempty"`
	ErrorCode    string `json:"error_code,omitempty"`
}

// Register performs the base DDI GET that provisions an unknown controller when
// the server enables gateway authentication. Existing controllers are refreshed.
func Register(ctx context.Context, profile config.HawkbitConfig) (RegisterResult, error) {
	if profile.TokenType != "gateway" {
		err := &CheckError{Code: "CONFIGURATION", Message: "manual registration requires a GatewayToken"}
		return RegisterResult{ErrorCode: err.Code, Error: err.Message}, err
	}
	result, err := Check(ctx, profile)
	return RegisterResult{Registered: result.Valid, HTTPStatus: result.HTTPStatus,
		ServerURL: result.ServerURL, ControllerID: result.ControllerID, PollingSleep: result.PollingSleep,
		Error: result.Error, ErrorCode: result.ErrorCode}, err
}
