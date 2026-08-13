package daemon

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/encedo/encedo-wg-hsm/internal/ipc"
)

// Everything here runs over a real unix socket. What it does not use is a
// device, an interface or a capability: the tunnel is a stub, which is the whole
// reason Open is a function rather than an import.

// stubTunnel stands in for the thing that would need netlink. It records that it
// ran, and stops when its context is cancelled.
type stubTunnel struct {
	mu       sync.Mutex
	started  chan struct{}
	stopped  chan struct{}
	refresh  chan string
	runErr   error
	emitOnce ipc.Event
}

func newStub() *stubTunnel {
	return &stubTunnel{
		started: make(chan struct{}, 1),
		stopped: make(chan struct{}, 1),
		refresh: make(chan string, 4),
	}
}

func (s *stubTunnel) Run(ctx context.Context, emit func(ipc.Event)) error {
	s.started <- struct{}{}
	if s.emitOnce.State != "" {
		emit(s.emitOnce)
	}
	<-ctx.Done()
	s.stopped <- struct{}{}
	return s.runErr
}

func (s *stubTunnel) Refresh(token string) error {
	s.refresh <- token
	return nil
}

// serve starts a daemon on a socket in a temporary directory and returns a
// connected client.
func serve(t *testing.T, open Open) (*Server, net.Conn) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close(); os.Remove(path) })

	s := &Server{Open: open, Build: ipc.Current()}
	go s.Serve(ln)

	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return s, c
}

func startReq() ipc.Request {
	return ipc.Request{
		Op: ipc.OpStart, Build: ipc.Current(),
		HEMURL: "https://my.ence.do", Identity: "aa", Peer: "bb", Token: "t",
	}
}

func reply(t *testing.T, c net.Conn) ipc.Reply {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		raw, err := ipc.ReadMsg(c)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		m, err := ipc.DecodeMsg(raw)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if m.Type == ipc.TypeReply {
			return *m.Reply
		}
	}
}

func TestStartRunsATunnel(t *testing.T) {
	stub := newStub()
	_, c := serve(t, func(context.Context, ipc.Request) (Tunnel, error) { return stub, nil })

	if err := ipc.WriteMsg(c, startReq()); err != nil {
		t.Fatalf("write: %v", err)
	}
	if r := reply(t, c); !r.OK {
		t.Fatalf("start refused: %s", r.Err)
	}
	select {
	case <-stub.started:
	case <-time.After(2 * time.Second):
		t.Fatal("the tunnel was never run")
	}
}

// The rule the architecture calls "no window, no tunnel". The component could
// keep running without one — it makes its own device calls — so this is enforced
// rather than inherent, and it is the connection closing that enforces it.
func TestClosingTheConnectionTakesTheTunnelDown(t *testing.T) {
	stub := newStub()
	s, c := serve(t, func(context.Context, ipc.Request) (Tunnel, error) { return stub, nil })

	ipc.WriteMsg(c, startReq())
	reply(t, c)
	<-stub.started

	c.Close()

	select {
	case <-stub.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("the window went away and the tunnel stayed up")
	}
	deadline := time.Now().Add(time.Second)
	for s.Running() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.Running() {
		t.Error("the daemon still believes a tunnel is running")
	}
}

func TestStopTakesTheTunnelDownAndLeavesTheConnection(t *testing.T) {
	stub := newStub()
	_, c := serve(t, func(context.Context, ipc.Request) (Tunnel, error) { return stub, nil })

	ipc.WriteMsg(c, startReq())
	reply(t, c)
	<-stub.started

	ipc.WriteMsg(c, ipc.Request{Op: ipc.OpStop})
	if r := reply(t, c); !r.OK {
		t.Fatalf("stop refused: %s", r.Err)
	}
	select {
	case <-stub.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("stop did not stop it")
	}
}

// One window, one tunnel. A second start has to be told, not queued.
func TestASecondStartIsRefused(t *testing.T) {
	stub := newStub()
	_, c := serve(t, func(context.Context, ipc.Request) (Tunnel, error) { return stub, nil })

	ipc.WriteMsg(c, startReq())
	reply(t, c)
	<-stub.started

	ipc.WriteMsg(c, startReq())
	r := reply(t, c)
	if r.OK {
		t.Fatal("a second tunnel was started")
	}
	if !strings.Contains(r.Err, "already running") {
		t.Errorf("refusal is %q; it should say a tunnel is already up", r.Err)
	}
}

// The record dialect is part of the build, and a mismatch would otherwise
// surface as a MAC failure — which looks like a tampered configuration.
func TestAMismatchedBuildIsRefusedByName(t *testing.T) {
	_, c := serve(t, func(context.Context, ipc.Request) (Tunnel, error) {
		t.Fatal("a mismatched window was allowed to open a tunnel")
		return nil, nil
	})

	req := startReq()
	req.Build.Descr = req.Build.Descr / 2 // the other dialect
	ipc.WriteMsg(c, req)

	r := reply(t, c)
	if r.OK {
		t.Fatal("a build speaking the other record dialect was accepted")
	}
	if !strings.Contains(r.Err, ipc.Current().String()) {
		t.Errorf("the refusal does not name this component's build: %q", r.Err)
	}
}

func TestAnInvalidRequestIsRefusedAndTheConnectionSurvives(t *testing.T) {
	stub := newStub()
	_, c := serve(t, func(context.Context, ipc.Request) (Tunnel, error) { return stub, nil })

	// No identity: the token names one key and means nothing without it.
	bad := startReq()
	bad.Identity = ""
	ipc.WriteMsg(c, bad)
	if r := reply(t, c); r.OK {
		t.Fatal("a start with no identity was accepted")
	}

	// The same connection must still be usable — a refusal is not a hang-up.
	ipc.WriteMsg(c, startReq())
	if r := reply(t, c); !r.OK {
		t.Fatalf("the connection was unusable after a refusal: %s", r.Err)
	}
}

func TestAnOpenThatRefusesLeavesNoSessionBehind(t *testing.T) {
	want := errors.New("the device said no")
	s, c := serve(t, func(context.Context, ipc.Request) (Tunnel, error) { return nil, want })

	ipc.WriteMsg(c, startReq())
	r := reply(t, c)
	if r.OK {
		t.Fatal("a start was reported as successful although opening failed")
	}
	if s.Running() {
		t.Error("a failed start left the daemon believing a tunnel is up; nothing could start after that")
	}
}

func TestEventsReachTheWindow(t *testing.T) {
	stub := newStub()
	stub.emitOnce = ipc.Event{State: "connected", Peer: "blbx", Rx: 860}
	_, c := serve(t, func(context.Context, ipc.Request) (Tunnel, error) { return stub, nil })

	ipc.WriteMsg(c, startReq())

	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var got *ipc.Event
	for got == nil {
		raw, err := ipc.ReadMsg(c)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		m, err := ipc.DecodeMsg(raw)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if m.Type == ipc.TypeEvent {
			got = m.Event
		}
	}
	if got.State != "connected" || got.Peer != "blbx" || got.Rx != 860 {
		t.Errorf("event arrived as %+v", *got)
	}
}

func TestRefreshReachesTheTunnel(t *testing.T) {
	stub := newStub()
	_, c := serve(t, func(context.Context, ipc.Request) (Tunnel, error) { return stub, nil })

	ipc.WriteMsg(c, startReq())
	reply(t, c)
	<-stub.started

	ipc.WriteMsg(c, ipc.Request{Op: ipc.OpRefresh, Token: "a fresher one"})
	if r := reply(t, c); !r.OK {
		t.Fatalf("refresh refused: %s", r.Err)
	}
	select {
	case tok := <-stub.refresh:
		if tok != "a fresher one" {
			t.Errorf("the tunnel was given %q", tok)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the token never reached the tunnel")
	}
}

func TestRefreshWithNothingRunningIsRefused(t *testing.T) {
	_, c := serve(t, func(context.Context, ipc.Request) (Tunnel, error) { return newStub(), nil })

	ipc.WriteMsg(c, ipc.Request{Op: ipc.OpRefresh, Token: "t"})
	if r := reply(t, c); r.OK {
		t.Fatal("a token was accepted for a tunnel that does not exist")
	}
}
