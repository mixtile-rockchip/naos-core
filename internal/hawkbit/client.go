// Package hawkbit maintains the DDI heartbeat independently of the external
// updater. Only rauc-hawkbit-updater follows deployment links and installs.
package hawkbit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"naos.local/core/internal/config"
)

const maxResponse = 64 * 1024

var identifier = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]+$`)

func validToken(token string) bool {
	return len(token) >= 8 && len(token) <= 1024 && tokenPattern.MatchString(token)
}

func tokenAuthentication(kind string) (scheme, key string, err error) {
	switch kind {
	case "", "target":
		return "TargetToken", "auth_token", nil
	case "gateway":
		return "GatewayToken", "gateway_token", nil
	default:
		return "", "", errors.New("hawkBit token_type must be target or gateway")
	}
}

func validate(cfg config.HawkbitConfig) (*url.URL, error) {
	if _, _, err := tokenAuthentication(cfg.TokenType); err != nil {
		return nil, err
	}
	u, err := url.Parse(cfg.ServerURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("hawkBit server must be an HTTP(S) origin without credentials or path")
	}
	if !identifier.MatchString(cfg.Tenant) || !identifier.MatchString(cfg.ControllerID) || !validToken(cfg.Token) {
		return nil, errors.New("hawkBit tenant, controller identifier or token is invalid")
	}
	if cfg.PollInterval < time.Second || cfg.PollInterval > 24*time.Hour || cfg.Timeout < time.Second || cfg.Timeout > 5*time.Minute {
		return nil, errors.New("hawkBit polling interval or timeout is outside supported limits")
	}
	if !filepath.IsAbs(cfg.DownloadPath) || cfg.DownloadPath == "/" || filepath.Clean(cfg.DownloadPath) != cfg.DownloadPath || strings.ContainsAny(cfg.DownloadPath, "\\\r\n\x00") {
		return nil, errors.New("hawkBit download directory must be an absolute clean path without INI escapes")
	}
	return u, nil
}

func pollingSleep(value string) (time.Duration, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 3 || len(parts[0]) != 2 || len(parts[1]) != 2 || len(parts[2]) != 2 {
		return 0, errors.New("invalid hawkBit polling.sleep")
	}
	values := [3]int{}
	for i, part := range parts {
		for _, c := range part {
			if c < '0' || c > '9' {
				return 0, errors.New("invalid hawkBit polling.sleep")
			}
		}
		values[i], _ = strconv.Atoi(part)
	}
	if values[0] > 23 || values[1] > 59 || values[2] > 59 {
		return 0, errors.New("invalid hawkBit polling.sleep")
	}
	d := time.Duration(values[0])*time.Hour + time.Duration(values[1])*time.Minute + time.Duration(values[2])*time.Second
	if d < time.Second {
		return 0, errors.New("invalid hawkBit polling.sleep")
	}
	return d, nil
}

type pollResponse struct {
	Status     int
	Sleep      time.Duration
	Action     string
	ConfigData bool
}

func poll(ctx context.Context, client *http.Client, origin *url.URL, cfg config.HawkbitConfig) (pollResponse, error) {
	scheme, _, err := tokenAuthentication(cfg.TokenType)
	if err != nil {
		return pollResponse{}, err
	}
	u := *origin
	u.Path = "/" + cfg.Tenant + "/controller/v1/" + cfg.ControllerID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return pollResponse{}, errors.New("cannot create hawkBit heartbeat")
	}
	req.Header.Set("Authorization", scheme+" "+cfg.Token)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		// net/url errors can contain URLs supplied by a hostile redirect. Never
		// propagate those or response bodies into the public status/logger.
		return pollResponse{}, errors.New("hawkBit heartbeat failed (network, TLS or deadline)")
	}
	defer resp.Body.Close()
	result := pollResponse{Status: resp.StatusCode}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil || len(data) > maxResponse {
		return result, errors.New("hawkBit heartbeat response exceeds limit or cannot be read")
	}
	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("hawkBit heartbeat returned HTTP %d", resp.StatusCode)
	}
	var body struct {
		Config struct {
			Polling struct {
				Sleep string `json:"sleep"`
			} `json:"polling"`
		} `json:"config"`
		Links map[string]json.RawMessage `json:"_links"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if decoder.Decode(&body) != nil || decoder.Decode(new(any)) != io.EOF {
		return result, errors.New("invalid hawkBit heartbeat JSON")
	}
	result.Sleep, err = pollingSleep(body.Config.Polling.Sleep)
	if err != nil {
		return result, err
	}
	// Relation names are hints only. No action URL or server text is retained.
	if _, ok := body.Links["deploymentBase"]; ok {
		result.Action = "deployment"
	}
	if _, ok := body.Links["cancelAction"]; ok {
		result.Action = "cancel"
	}
	_, result.ConfigData = body.Links["configData"]
	return result, nil
}

func ini(cfg config.HawkbitConfig, origin *url.URL) []byte {
	_, tokenKey, err := tokenAuthentication(cfg.TokenType)
	if err != nil {
		return nil
	}
	seconds := int((cfg.Timeout + time.Second - 1) / time.Second)
	return []byte(fmt.Sprintf("[client]\nhawkbit_server=%s\ntenant_id=%s\ntarget_name=%s\n%s=%s\nssl=%t\nssl_verify=true\nstream_bundle=false\nbundle_download_location=%s\npost_update_reboot=false\nconnect_timeout=%d\ntimeout=%d\n[device]\nsource=naos-core\n", origin.Host, cfg.Tenant, cfg.ControllerID, tokenKey, cfg.Token, origin.Scheme == "https", filepath.Join(cfg.DownloadPath, "hawkbit.raucb"), seconds, seconds))
}

func hash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func privateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return errors.New("cannot create private hawkBit directory")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("hawkBit directory must not be a symlink")
	}
	// Refuse a pre-existing shared directory instead of silently changing its
	// permissions (DownloadPath may be configured by the administrator).
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("hawkBit directory must already be private (0700)")
	}
	return nil
}

func atomicWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".hawkbit-*")
	if err != nil {
		return errors.New("cannot create private hawkBit file")
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return errors.New("cannot protect hawkBit file")
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.New("cannot write or sync hawkBit file")
	}
	if err := os.Rename(temporary, path); err != nil {
		return errors.New("cannot publish hawkBit file")
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errors.New("cannot open hawkBit directory for sync")
	}
	defer directory.Close()
	if directory.Sync() != nil {
		return errors.New("cannot sync hawkBit directory")
	}
	return nil
}
