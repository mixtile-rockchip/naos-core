package hawkbit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReadSystemAttributes(t *testing.T) {
	base := "NAME=Alpine\nVERSION_ID='3.24.3'\nID=alpine\n"
	for _, tc := range []struct {
		name, version, release string
		want                   map[string]string
		wantErr                bool
	}{
		{
			name:    "firmware takes precedence over base OS",
			version: `{"version":"0.0.2","build_id":"build-123","machine":"mixtile-core3588e-v2","private":"not-exported"}`,
			release: base,
			want:    map[string]string{"system_version": "0.0.2", "system_name": "NAOS", "system_build_id": "build-123", "system_machine": "mixtile-core3588e-v2", "os_name": "Alpine", "os_version": "3.24.3", "os_id": "alpine"},
		},
		{
			name: "firmware without optional fields or os-release", version: `{"version":"0.0.3"}`,
			want: map[string]string{"system_version": "0.0.3", "system_name": "NAOS"},
		},
		{
			name: "missing firmware falls back to quoted os-release",
			release: `# comment
NAME="Alpine \"edge\" Linux" # comment
VERSION_ID='3.24.3'
VERSION="ignored fallback"
ID=alpine
IGNORED_SECRET="not-exported"
`,
			want: map[string]string{"system_version": "3.24.3", "system_name": `Alpine "edge" Linux`, "system_id": "alpine", "os_name": `Alpine "edge" Linux`, "os_version": "3.24.3", "os_id": "alpine"},
		},
		{
			name: "VERSION and PRETTY_NAME fallback", release: "VERSION_ID=\nVERSION='3.24 stable'\nPRETTY_NAME=Alpine\\ Linux\nID=alpine\n",
			want: map[string]string{"system_version": "3.24 stable", "system_name": "Alpine Linux", "system_id": "alpine", "os_version": "3.24 stable", "os_name": "Alpine Linux", "os_id": "alpine"},
		},
		{name: "missing all metadata", wantErr: true},
		{name: "missing versions", release: "NAME=Alpine\nID=alpine\n", wantErr: true},
		{name: "invalid firmware cannot masquerade as Alpine", version: "not-json", release: base, wantErr: true},
		{name: "firmware missing version cannot fall back", version: `{"build_id":"build-123"}`, release: base, wantErr: true},
		{name: "oversize firmware", version: strings.Repeat("x", maxVersionMetadata+1), release: base, wantErr: true},
		{name: "oversize release", release: strings.Repeat("x", maxVersionMetadata+1), wantErr: true},
		{name: "oversize version value", version: `{"version":"` + strings.Repeat("x", maxAttributeValue+1) + `"}`, wantErr: true},
		{name: "control character in version", version: `{"version":"1\n2"}`, wantErr: true},
		{name: "unterminated quote", release: "VERSION_ID=\"unterminated\n", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			versionPath, releasePath := filepath.Join(directory, "version.json"), filepath.Join(directory, "os-release")
			for path, content := range map[string]string{versionPath: tc.version, releasePath: tc.release} {
				if content != "" {
					if err := os.WriteFile(path, []byte(content), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			attrs, err := readSystemAttributes(versionPath, releasePath)
			if (err != nil) != tc.wantErr || !reflect.DeepEqual(attrs, tc.want) {
				t.Fatalf("unexpected metadata result: attrs=%v err=%v", attrs, err)
			}
		})
	}
}

func TestReleaseValueDoesNotEvaluateShell(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "must-not-exist")
	raw := `"$(touch ` + marker + `) \$HOME \\ end"`
	value, err := releaseValue(raw)
	if err != nil || value != "$(touch "+marker+") $HOME \\ end" {
		t.Fatalf("literal shell syntax changed: %q %v", value, err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("os-release value executed a shell command")
	}
	for _, raw := range []string{`'unterminated`, `"unterminated`, `"ok" garbage`, `trailing\`} {
		if _, err := releaseValue(raw); err == nil {
			t.Fatal("malformed os-release value was accepted")
		}
	}
}

type attributesTransport func(*http.Request) (*http.Response, error)

func (f attributesTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestReportAttributesAuthenticationAndProtocol(t *testing.T) {
	for _, kind := range []string{"target", "gateway"} {
		t.Run(kind, func(t *testing.T) {
			cfg := fixtureConfig(t, "https://hawkbit.invalid")
			cfg.TokenType = kind
			origin, _ := url.Parse(cfg.ServerURL)
			original := *origin
			attrs := map[string]string{"system_name": "NAOS", "system_version": "0.0.2", "os_version": "3.24.3"}
			calls := 0
			client := &http.Client{Transport: attributesTransport(func(request *http.Request) (*http.Response, error) {
				calls++
				scheme, _, _ := tokenAuthentication(kind)
				if request.Method != http.MethodPut || request.URL.String() != "https://hawkbit.invalid/DEFAULT/controller/v1/fixture-01/configData" || request.Header.Get("Authorization") != scheme+" "+cfg.Token || request.Header.Get("Content-Type") != "application/json" {
					t.Fatal("incorrect attributes request endpoint, method, or headers")
				}
				var payload struct {
					Mode   string            `json:"mode"`
					Data   map[string]string `json:"data"`
					Status json.RawMessage   `json:"status"`
				}
				if err := json.NewDecoder(request.Body).Decode(&payload); err != nil || payload.Mode != "merge" || !reflect.DeepEqual(payload.Data, attrs) || payload.Status != nil {
					t.Fatal("attributes payload differs from hawkBit 1.1.0 configData protocol")
				}
				return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
			})}
			if err := reportAttributes(context.Background(), client, origin, cfg, attrs); err != nil || calls != 1 || *origin != original {
				t.Fatalf("report failed or mutated the origin: %v", err)
			}
		})
	}
}

func TestReportAttributesRejectsBadResponsesWithoutLeaking(t *testing.T) {
	for _, code := range []int{200, 201, 204, 302, 400, 401, 500} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			cfg := fixtureConfig(t, "https://hawkbit.invalid")
			origin, _ := url.Parse(cfg.ServerURL)
			calls := 0
			client := &http.Client{Transport: attributesTransport(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(cfg.Token + " server-private-message")), Header: http.Header{"Location": {"https://foreign.invalid/" + cfg.Token}}}, nil
			})}
			err := reportAttributes(context.Background(), client, origin, cfg, map[string]string{"system_version": "0.0.2"})
			if (err != nil) != (code < 200 || code >= 300) || calls != 1 {
				t.Fatal("HTTP status handling or redirect protection failed")
			}
			if err != nil && (strings.Contains(err.Error(), cfg.Token) || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "foreign")) {
				t.Fatal("error exposed a token, response body, or redirect URL")
			}
		})
	}
	for name, transport := range map[string]attributesTransport{
		"oversize response": func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxResponse+1)))}, nil
		},
		"network error": func(*http.Request) (*http.Response, error) {
			return nil, errors.New("server-private-message fixture-secret-token")
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := fixtureConfig(t, "https://hawkbit.invalid")
			origin, _ := url.Parse(cfg.ServerURL)
			err := reportAttributes(context.Background(), &http.Client{Transport: transport}, origin, cfg, map[string]string{"system_version": "0.0.2"})
			if err == nil || strings.Contains(err.Error(), cfg.Token) || strings.Contains(err.Error(), "private") {
				t.Fatal("response limit or error redaction failed")
			}
		})
	}
}

func TestReportAttributesDoesNotSendMissingOrInvalidVersion(t *testing.T) {
	cfg := fixtureConfig(t, "https://hawkbit.invalid")
	origin, _ := url.Parse(cfg.ServerURL)
	client := &http.Client{Transport: attributesTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid or missing system version reached the network")
		return nil, nil
	})}
	for _, attrs := range []map[string]string{nil, {}, {"system_name": "NAOS"}, {"system_version": " "}, {"system_version": strings.Repeat("x", maxAttributeValue+1)}, {"system_version": "1\n2"}} {
		if err := reportAttributes(context.Background(), client, origin, cfg, attrs); err == nil {
			t.Fatal("missing or invalid version was accepted")
		}
	}
}
