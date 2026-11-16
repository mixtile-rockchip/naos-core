package operation

import (
	"errors"
	"sync"
	"testing"
)

func TestLeaseCannotReleaseLaterOperation(t *testing.T) {
	g := New()
	old, err := g.TryAcquire("download")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.TryAcquire("recovery"); !errors.Is(err, ErrBusy) {
		t.Fatal("parallel mutation admitted")
	}
	old.Release()
	current, err := g.TryAcquire("reboot")
	if err != nil {
		t.Fatal(err)
	}
	old.Release()
	if !g.Busy() || g.Kind() != "reboot" {
		t.Fatal("old lease released a newer owner")
	}
	current.Release()
	if g.Busy() {
		t.Fatal("lease not released")
	}
}
func TestGateRaceOnlyOneWinner(t *testing.T) {
	g := New()
	start := make(chan struct{})
	var mu sync.Mutex
	winners := []*Lease{}
	var group sync.WaitGroup
	for i := 0; i < 20; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			if l, err := g.TryAcquire("update"); err == nil {
				mu.Lock()
				winners = append(winners, l)
				mu.Unlock()
			}
		}()
	}
	close(start)
	group.Wait()
	if len(winners) != 1 {
		t.Fatalf("winners %d", len(winners))
	}
	winners[0].Release()
}
