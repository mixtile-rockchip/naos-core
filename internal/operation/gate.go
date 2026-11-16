// Package operation serializes firmware changes, online downloads and resets.
package operation

import (
	"errors"
	"sync"
)

var ErrBusy = errors.New("another device operation is active")

type Gate struct {
	mu     sync.Mutex
	active *Lease
}
type Lease struct {
	gate *Gate
	kind string
}

func New() *Gate { return &Gate{} }
func (g *Gate) TryAcquire(kind string) (*Lease, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active != nil {
		return nil, ErrBusy
	}
	lease := &Lease{gate: g, kind: kind}
	g.active = lease
	return lease, nil
}
func (g *Gate) Busy() bool { g.mu.Lock(); defer g.mu.Unlock(); return g.active != nil }
func (g *Gate) Kind() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active == nil {
		return ""
	}
	return g.active.kind
}
func (l *Lease) Release() {
	if l == nil || l.gate == nil {
		return
	}
	g := l.gate
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active == l {
		g.active = nil
	}
}
