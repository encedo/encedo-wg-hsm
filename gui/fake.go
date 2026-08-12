package main

import (
	"context"
	"errors"
	"sync"
	"time"
)

// fakeSession stands in for the tunnel while the flow is being worked out. It
// exists so the interface can be exercised on all three platforms before any of
// it touches a device, and so the shape of Session is settled by the thing that
// consumes it rather than guessed at from the other side.
//
// It runs on a compressed clock: rekeys every few seconds instead of every two
// minutes, and a session that expires in a minute rather than eight hours. The
// point is to reach the interesting states while somebody is watching.
type fakeSession struct {
	events chan Event

	mu     sync.Mutex
	state  State
	peer   string
	expiry time.Time
	last   time.Time
	rx, tx uint64
	closed bool

	stop chan struct{}
}

// Compressed timings. Real ones are ~120 s between handshakes and hours of
// session; nobody can test a flow at that speed.
const (
	fakeRekeyEvery = 4 * time.Second
	fakeSessionLen = 90 * time.Second
	fakeConnectFor = 1200 * time.Millisecond
)

func newFakeSession() *fakeSession {
	f := &fakeSession{
		events: make(chan Event, 16),
		state:  NoModule,
		stop:   make(chan struct{}),
	}
	go f.run()
	return f
}

func (f *fakeSession) Events() <-chan Event { return f.events }

func (f *fakeSession) Connect(ctx context.Context, passphrase []byte) error {
	f.mu.Lock()
	if f.state != Ready {
		f.mu.Unlock()
		return errors.New("no module, or already connected")
	}
	if len(passphrase) == 0 {
		f.mu.Unlock()
		return errors.New("the passphrase is empty")
	}
	f.state = Connecting
	f.mu.Unlock()
	f.emit()

	go func() {
		select {
		case <-time.After(fakeConnectFor):
		case <-ctx.Done():
			return
		}
		f.mu.Lock()
		f.state = Connected
		f.peer = "head office"
		f.expiry = time.Now().Add(fakeSessionLen)
		f.last = time.Now()
		f.mu.Unlock()
		f.emit()
	}()
	return nil
}

func (f *fakeSession) Disconnect() error {
	f.mu.Lock()
	if f.state != Connected {
		f.mu.Unlock()
		return errors.New("not connected")
	}
	f.state = Disconnecting
	f.mu.Unlock()
	f.emit()

	go func() {
		time.Sleep(400 * time.Millisecond)
		f.mu.Lock()
		f.state = Ready
		f.peer, f.rx, f.tx = "", 0, 0
		f.expiry, f.last = time.Time{}, time.Time{}
		f.mu.Unlock()
		f.emit()
	}()
	return nil
}

func (f *fakeSession) Close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	f.state = Ended
	f.mu.Unlock()
	close(f.stop)
	return nil
}

// -- controls the debug panel drives, so the states that are awkward to reach
//    on real hardware can be reached on demand ---------------------------------

func (f *fakeSession) setModulePresent(present bool) {
	f.mu.Lock()
	switch {
	case !present:
		f.state = NoModule
		f.peer = ""
	case f.state == NoModule:
		f.state = Ready
	}
	f.mu.Unlock()
	f.emit()
}

func (f *fakeSession) triggerFailover() {
	f.mu.Lock()
	if f.state != Connected {
		f.mu.Unlock()
		return
	}
	f.peer = "backup site"
	f.last = time.Now()
	f.mu.Unlock()
	f.emitNotice(`Moved to "backup site" — "head office" stopped answering`)
}

func (f *fakeSession) expireNow() {
	f.mu.Lock()
	if f.state != Connected {
		f.mu.Unlock()
		return
	}
	f.expiry = time.Now()
	f.mu.Unlock()
}

// run advances the tunnel: handshakes while connected, and the end of the
// session when the token runs out. Expiry ends the tunnel rather than renewing
// it, which is the behaviour the real client has and the interface has to make
// legible rather than hide.
func (f *fakeSession) run() {
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	last := time.Now()

	for {
		select {
		case <-f.stop:
			close(f.events)
			return
		case now := <-tick.C:
			f.mu.Lock()
			if f.state != Connected {
				f.mu.Unlock()
				continue
			}
			if !f.expiry.IsZero() && now.After(f.expiry) {
				f.state = Ready
				f.peer = ""
				f.expiry, f.last = time.Time{}, time.Time{}
				f.mu.Unlock()
				f.emitNotice("the session has expired — connect again to continue")
				continue
			}
			f.rx += 1400
			f.tx += 900
			rekeyed := now.Sub(last) >= fakeRekeyEvery
			if rekeyed {
				f.last = now
				last = now
			}
			f.mu.Unlock()
			f.emit()
		}
	}
}

func (f *fakeSession) snapshot() Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return Event{
		State: f.state, Peer: f.peer, ExpiresAt: f.expiry,
		LastHandshake: f.last, Rx: f.rx, Tx: f.tx,
	}
}

func (f *fakeSession) emit() { f.send(f.snapshot()) }

func (f *fakeSession) emitNotice(notice string) {
	e := f.snapshot()
	e.Notice = notice
	f.send(e)
}

// send never blocks: a window that has stopped reading must not be able to
// wedge the session behind it.
func (f *fakeSession) send(e Event) {
	f.mu.Lock()
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return
	}
	select {
	case f.events <- e:
	default:
	}
}
