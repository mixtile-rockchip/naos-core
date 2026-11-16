// Package mdns manages persistent Avahi service declarations through files.
package mdns

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	filePrefix  = "naos-core-"
	fileSuffix  = ".service"
	maxServices = 32
	maxXMLBytes = 16 * 1024
)

var (
	ErrInvalid     = errors.New("invalid mDNS service")
	ErrNotFound    = errors.New("mDNS service not found")
	ErrConflict    = errors.New("mDNS service limit reached")
	ErrUnavailable = errors.New("Avahi service files unavailable")
)

type Service struct {
	Name string            `json:"name"`
	Type string            `json:"type"`
	Port uint16            `json:"port"`
	Host string            `json:"host,omitempty"`
	TXT  map[string]string `json:"txt,omitempty"`
}

type Registration struct {
	ID string `json:"id"`
	Service
	State string `json:"state"`
}

type declaration struct {
	XMLName  xml.Name          `xml:"service-group"`
	Name     string            `xml:"name"`
	Services []declaredService `xml:"service"`
}

type declaredService struct {
	Type string   `xml:"type"`
	Host string   `xml:"host-name,omitempty"`
	Port uint16   `xml:"port"`
	TXT  []string `xml:"txt-record"`
}

// Manager owns no bus connection or goroutine. Declarations survive business
// and Core shutdown until explicitly updated or deleted.
type Manager struct {
	mu        sync.Mutex
	directory string
	hostname  func() (string, error)
	available func() error
	closed    bool
}

func New() *Manager {
	return &Manager{directory: "/etc/avahi/services", hostname: os.Hostname, available: func() error {
		info, err := os.Stat("/usr/sbin/avahi-daemon")
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
			return errors.New("avahi-daemon is not executable")
		}
		return nil
	}}
}

func unavailable(err error) error { return fmt.Errorf("%w: %v", ErrUnavailable, err) }

func (m *Manager) ready(ctx context.Context) error {
	if m.closed {
		return unavailable(errors.New("manager closed"))
	}
	if err := ctx.Err(); err != nil {
		return unavailable(err)
	}
	if err := m.available(); err != nil {
		return unavailable(err)
	}
	info, err := os.Stat(m.directory)
	if err != nil {
		return unavailable(err)
	}
	if !info.IsDir() {
		return unavailable(errors.New("service path is not a directory"))
	}
	return nil
}

func validID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for i, b := range []byte(id) {
		alnum := b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
		if !alnum && !(i > 0 && (b == '-' || b == '_' || b == '.')) {
			return false
		}
	}
	return true
}

func managedID(name string) (string, bool) {
	if !strings.HasPrefix(name, filePrefix) || !strings.HasSuffix(name, fileSuffix) {
		return "", false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(name, filePrefix), fileSuffix)
	return id, validID(id)
}

func validText(text string) bool {
	if !utf8.ValidString(text) {
		return false
	}
	for _, r := range text {
		if unicode.IsControl(r) || r == 0xfffe || r == 0xffff {
			return false
		}
	}
	return true
}

func validate(id string, s Service) (Service, []string, error) {
	bad := func(reason string) (Service, []string, error) {
		return Service{}, nil, fmt.Errorf("%w: %s", ErrInvalid, reason)
	}
	if !validID(id) {
		return bad("id must be 1-64 letters, digits, dot, hyphen or underscore, beginning with a letter or digit")
	}
	if len(s.Name) == 0 || len(s.Name) > 63 || strings.TrimSpace(s.Name) == "" || !validText(s.Name) {
		return bad("name must contain 1-63 UTF-8 bytes without control characters")
	}
	s.Type = strings.ToLower(s.Type)
	body, ok := strings.CutPrefix(s.Type, "_")
	if !ok {
		return bad("type must be _service._tcp or _service._udp")
	}
	label, protocol, ok := strings.Cut(body, ".")
	if !ok || (protocol != "_tcp" && protocol != "_udp") || len(label) < 1 || len(label) > 15 || label[0] == '-' || label[len(label)-1] == '-' {
		return bad("type must be _service._tcp or _service._udp")
	}
	letter := false
	for _, b := range []byte(label) {
		if b >= 'a' && b <= 'z' {
			letter = true
		} else if (b < '0' || b > '9') && b != '-' {
			return bad("invalid service type")
		}
	}
	if !letter || s.Port == 0 {
		return bad("type needs a letter and port must be 1-65535")
	}
	if len(s.TXT) > 32 {
		return bad("at most 32 TXT fields are allowed")
	}
	keys, seen, total := make([]string, 0, len(s.TXT)), make(map[string]bool), 0
	copyTXT := make(map[string]string, len(s.TXT))
	for key, value := range s.TXT {
		if key == "" || !validText(value) {
			return bad("TXT text must contain valid UTF-8 without control characters")
		}
		for _, b := range []byte(key) {
			if b < 0x20 || b > 0x7e || b == '=' {
				return bad("TXT keys must be printable ASCII without equals")
			}
		}
		fold := strings.ToLower(key)
		if seen[fold] {
			return bad("TXT keys must be unique ignoring case")
		}
		seen[fold] = true
		size := len(key) + 1 + len(value)
		total += size + 1
		if size > 255 || total > 1024 {
			return bad("TXT item exceeds 255 bytes or total exceeds 1024 bytes")
		}
		keys, copyTXT[key] = append(keys, key), value
	}
	sort.Strings(keys)
	txt := make([]string, 0, len(keys))
	for _, key := range keys {
		txt = append(txt, key+"="+copyTXT[key])
	}
	s.TXT = copyTXT
	return s, txt, nil
}

func (m *Manager) currentHost() (string, error) {
	host, err := m.hostname()
	if err != nil {
		return "", unavailable(err)
	}
	host = strings.TrimSuffix(host, ".")
	if !strings.HasSuffix(strings.ToLower(host), ".local") {
		host += ".local"
	}
	if len(host) > 253 {
		return "", unavailable(errors.New("invalid system hostname"))
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", unavailable(errors.New("invalid system hostname"))
		}
		for _, b := range []byte(label) {
			if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-') {
				return "", unavailable(errors.New("invalid system hostname"))
			}
		}
	}
	return host, nil
}

func (m *Manager) Put(ctx context.Context, id string, s Service) (Registration, error) {
	s, txt, err := validate(id, s)
	if err != nil {
		return Registration{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err = m.ready(ctx); err != nil {
		return Registration{}, err
	}
	host, err := m.currentHost()
	if err != nil {
		return Registration{}, err
	}
	if s.Host != "" && !strings.EqualFold(strings.TrimSuffix(s.Host, "."), host) {
		return Registration{}, fmt.Errorf("%w: host must be the device hostname; custom address aliases are not supported", ErrInvalid)
	}
	s.Host = host
	reg := Registration{ID: id, Service: s, State: "configured"}
	path := filepath.Join(m.directory, filePrefix+id+fileSuffix)
	old, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Registration{}, unavailable(err)
	}
	if err == nil {
		if !old.Mode().IsRegular() {
			return Registration{}, unavailable(errors.New("managed service is not a regular file"))
		}
		stored, err := read(path, id)
		if err != nil {
			return Registration{}, err
		}
		if stored.Host == "" || strings.EqualFold(strings.TrimSuffix(stored.Host, "."), host) {
			stored.Host = host
		}
		if reflect.DeepEqual(stored.Service, s) {
			return reg, nil
		}
	} else {
		files, err := os.ReadDir(m.directory)
		if err != nil {
			return Registration{}, unavailable(err)
		}
		count := 0
		for _, file := range files {
			if _, ok := managedID(file.Name()); ok {
				count++
			}
		}
		if count >= maxServices {
			return Registration{}, fmt.Errorf("%w: at most %d registrations are allowed", ErrConflict, maxServices)
		}
	}
	doc := declaration{Name: s.Name, Services: []declaredService{{Type: s.Type, Host: s.Host, Port: s.Port, TXT: txt}}}
	data, err := xml.MarshalIndent(doc, "", "  ")
	if err != nil {
		return Registration{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	data = append([]byte(xml.Header+"<!DOCTYPE service-group SYSTEM \"avahi-service.dtd\">\n"), append(data, '\n')...)
	file, err := os.CreateTemp(m.directory, ".naos-core-"+id+"-*")
	if err != nil {
		return Registration{}, unavailable(err)
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err = file.Chmod(0644); err != nil {
		return Registration{}, unavailable(err)
	}
	if _, err = file.Write(data); err != nil {
		return Registration{}, unavailable(err)
	}
	// Avahi reloads an existing path only if its seconds-resolution mtime
	// changes. Strictly increasing seconds handle rapid writes/clock rollback.
	mtime := time.Now()
	if old != nil && mtime.Unix() <= old.ModTime().Unix() {
		mtime = time.Unix(old.ModTime().Unix()+1, 0)
	}
	if err = os.Chtimes(file.Name(), mtime, mtime); err != nil {
		return Registration{}, unavailable(err)
	}
	if err = file.Sync(); err != nil {
		return Registration{}, unavailable(err)
	}
	if err = file.Close(); err != nil {
		return Registration{}, unavailable(err)
	}
	if err = os.Rename(file.Name(), path); err != nil {
		return Registration{}, unavailable(err)
	}
	return reg, nil
}

func read(path, id string) (Registration, error) {
	file, err := os.Open(path)
	if err != nil {
		return Registration{}, unavailable(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Registration{}, unavailable(err)
	}
	if !info.Mode().IsRegular() {
		return Registration{}, unavailable(errors.New("managed service is not a regular file"))
	}
	data, err := io.ReadAll(io.LimitReader(file, maxXMLBytes+1))
	if err != nil {
		return Registration{}, unavailable(err)
	}
	if len(data) > maxXMLBytes {
		return Registration{}, unavailable(errors.New("service XML exceeds size limit"))
	}
	var doc declaration
	if err = xml.Unmarshal(data, &doc); err != nil {
		return Registration{}, unavailable(err)
	}
	if len(doc.Services) != 1 {
		return Registration{}, unavailable(errors.New("expected one service declaration"))
	}
	d := doc.Services[0]
	txt := make(map[string]string, len(d.TXT))
	for _, item := range d.TXT {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			return Registration{}, unavailable(errors.New("invalid stored TXT record"))
		}
		if _, exists := txt[key]; exists {
			return Registration{}, unavailable(errors.New("duplicate stored TXT key"))
		}
		txt[key] = value
	}
	s, _, err := validate(id, Service{Name: doc.Name, Type: d.Type, Port: d.Port, Host: d.Host, TXT: txt})
	if err != nil {
		return Registration{}, unavailable(err)
	}
	return Registration{ID: id, Service: s, State: "configured"}, nil
}

func (m *Manager) List(ctx context.Context) ([]Registration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ready(ctx); err != nil {
		return nil, err
	}
	files, err := os.ReadDir(m.directory)
	if err != nil {
		return nil, unavailable(err)
	}
	result := make([]Registration, 0)
	for _, file := range files {
		id, ok := managedID(file.Name())
		if !ok {
			continue
		}
		if file.Type()&os.ModeSymlink != 0 {
			return nil, unavailable(errors.New("managed service must not be a symlink"))
		}
		reg, err := read(filepath.Join(m.directory, file.Name()), id)
		if err != nil {
			return nil, err
		}
		result = append(result, reg)
	}
	return result, nil
}

func (m *Manager) Delete(ctx context.Context, id string) error {
	if !validID(id) {
		return fmt.Errorf("%w: invalid id", ErrInvalid)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ready(ctx); err != nil {
		return err
	}
	path := filepath.Join(m.directory, filePrefix+id+fileSuffix)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil {
		return unavailable(err)
	}
	if !info.Mode().IsRegular() {
		return unavailable(errors.New("managed service is not a regular file"))
	}
	if err = os.Remove(path); err != nil {
		return unavailable(err)
	}
	return nil
}

// Close does not delete persistent declarations.
func (m *Manager) Close() error { m.mu.Lock(); defer m.mu.Unlock(); m.closed = true; return nil }
