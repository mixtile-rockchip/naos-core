package hawkbit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"unicode/utf8"

	"naos.local/core/internal/config"
)

const (
	maxVersionMetadata = 64 * 1024
	maxAttributeValue  = 1024
)

// readSystemAttributes distinguishes the NAOS firmware version from its base
// OS. Only a missing NAOS metadata file permits falling back to os-release.
func readSystemAttributes(versionPath, osReleasePath string) (map[string]string, error) {
	data, versionErr := readVersionMetadata(versionPath)
	if versionErr != nil && !errors.Is(versionErr, os.ErrNotExist) {
		return nil, errors.New("cannot read system version metadata")
	}
	attrs := make(map[string]string)
	if versionErr == nil {
		var version struct {
			Version string `json:"version"`
			BuildID string `json:"build_id"`
			Machine string `json:"machine"`
		}
		if json.Unmarshal(data, &version) != nil || strings.TrimSpace(version.Version) == "" {
			return nil, errors.New("invalid system version metadata")
		}
		attrs["system_name"] = "NAOS"
		for key, value := range map[string]string{
			"system_version": version.Version, "system_build_id": version.BuildID, "system_machine": version.Machine,
		} {
			value = strings.TrimSpace(value)
			if !validAttributeValue(value) {
				return nil, errors.New("invalid system version metadata")
			}
			if value != "" {
				attrs[key] = value
			}
		}
	}
	osInfo, osErr := readOSRelease(osReleasePath)
	if osErr != nil {
		if versionErr == nil {
			return attrs, nil // Base-OS attributes are optional when firmware is known.
		}
		return nil, errors.New("cannot read system version metadata")
	}
	for key, value := range map[string]string{
		"os_name":    firstReleaseValue(osInfo, "NAME", "PRETTY_NAME", "ID"),
		"os_version": firstReleaseValue(osInfo, "VERSION_ID", "VERSION"), "os_id": osInfo["ID"],
	} {
		if value != "" {
			attrs[key] = value
		}
	}
	if versionErr != nil {
		if attrs["os_version"] == "" {
			return nil, errors.New("system version is unavailable")
		}
		attrs["system_version"] = attrs["os_version"]
		if attrs["os_name"] != "" {
			attrs["system_name"] = attrs["os_name"]
		}
		if attrs["os_id"] != "" {
			attrs["system_id"] = attrs["os_id"]
		}
	}
	return attrs, nil
}

func readVersionMetadata(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxVersionMetadata+1))
	if err != nil || len(data) > maxVersionMetadata {
		return nil, errors.New("invalid version metadata size or content")
	}
	return data, nil
}

func readOSRelease(path string) (map[string]string, error) {
	data, err := readVersionMetadata(path)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		key, raw, ok := strings.Cut(strings.TrimSpace(line), "=")
		key = strings.TrimSpace(key)
		if !ok || key != "VERSION_ID" && key != "VERSION" && key != "NAME" && key != "PRETTY_NAME" && key != "ID" {
			continue
		}
		value, err := releaseValue(strings.TrimSpace(raw))
		value = strings.TrimSpace(value)
		if err != nil || !validAttributeValue(value) {
			return nil, errors.New("invalid os-release value")
		}
		values[key] = value
	}
	return values, nil
}

// releaseValue handles the quoted assignment values used by os-release. It
// does not evaluate variables, command substitutions, or any shell program.
func releaseValue(raw string) (string, error) {
	var value strings.Builder
	var quote byte
	if len(raw) > 0 && (raw[0] == '\'' || raw[0] == '"') {
		quote, raw = raw[0], raw[1:]
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if quote != 0 && c == quote {
			tail := strings.TrimSpace(raw[i+1:])
			if tail != "" && !strings.HasPrefix(tail, "#") {
				return "", errors.New("invalid quoted os-release value")
			}
			return value.String(), nil
		}
		if quote == 0 && (c == ' ' || c == '\t' || c == '#') {
			if c == '#' && i > 0 { // A '#' inside an unquoted word is literal.
				value.WriteByte(c)
				continue
			}
			tail := strings.TrimSpace(raw[i:])
			if tail != "" && !strings.HasPrefix(tail, "#") {
				return "", errors.New("invalid unquoted os-release value")
			}
			return value.String(), nil
		}
		if c == '\\' && quote != '\'' {
			if i+1 == len(raw) {
				return "", errors.New("invalid escaped os-release value")
			}
			next := raw[i+1]
			if quote == 0 || strings.ContainsRune("\\\"$`", rune(next)) {
				value.WriteByte(next)
				i++
				continue
			}
		}
		value.WriteByte(c)
	}
	if quote != 0 {
		return "", errors.New("unterminated os-release value")
	}
	return value.String(), nil
}

func firstReleaseValue(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if values[key] != "" {
			return values[key]
		}
	}
	return ""
}

func validAttributeValue(value string) bool {
	return len(value) <= maxAttributeValue && utf8.ValidString(value) && strings.IndexFunc(value, func(r rune) bool {
		return r < 32 || r == 127
	}) < 0
}

// reportAttributes uses the configured origin rather than following a server
// supplied configData URL. hawkBit 1.1.0 requires mode/data, not action status.
func reportAttributes(ctx context.Context, client *http.Client, origin *url.URL, cfg config.HawkbitConfig, attrs map[string]string) error {
	if strings.TrimSpace(attrs["system_version"]) == "" || len(attrs) > 16 {
		return errors.New("system version attributes are unavailable")
	}
	for key, value := range attrs {
		if !identifier.MatchString(key) || value == "" || !validAttributeValue(value) {
			return errors.New("invalid system version attributes")
		}
	}
	scheme, _, err := tokenAuthentication(cfg.TokenType)
	if err != nil {
		return err
	}
	if client == nil || origin == nil || origin.User != nil || origin.Hostname() == "" ||
		(origin.Scheme != "http" && origin.Scheme != "https") || !identifier.MatchString(cfg.Tenant) ||
		!identifier.MatchString(cfg.ControllerID) || !validToken(cfg.Token) {
		return errors.New("invalid hawkBit attributes configuration")
	}
	body, err := json.Marshal(struct {
		Mode string            `json:"mode"`
		Data map[string]string `json:"data"`
	}{Mode: "merge", Data: attrs})
	if err != nil {
		return errors.New("cannot encode system version attributes")
	}
	u := *origin
	u.Path = "/" + cfg.Tenant + "/controller/v1/" + cfg.ControllerID + "/configData"
	u.RawPath, u.RawQuery, u.Fragment = "", "", ""
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), bytes.NewReader(body))
	if err != nil {
		return errors.New("cannot create hawkBit attributes request")
	}
	request.Header.Set("Authorization", scheme+" "+cfg.Token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	requestClient := *client
	requestClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := requestClient.Do(request)
	if err != nil {
		return errors.New("hawkBit attributes request failed (network, TLS or deadline)")
	}
	defer response.Body.Close()
	n, err := io.Copy(io.Discard, io.LimitReader(response.Body, maxResponse+1))
	if err != nil || n > maxResponse {
		return errors.New("hawkBit attributes response exceeds limit or cannot be read")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("hawkBit attributes update was rejected")
	}
	return nil
}
