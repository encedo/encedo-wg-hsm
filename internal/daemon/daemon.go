// Package daemon is the privileged half of the graphical client: it listens on
// a local socket, and when a window asks, it runs a tunnel.
//
// It knows nothing about netlink or wireguard-go. What it does with a start
// request arrives as a function, which is what lets everything here be tested
// over a real socket without a device, an interface or a capability — and what
// keeps the accept loop, the access control and the session rule readable
// alongside each other rather than buried in a file that also opens tunnels.
//
// One tunnel at a time, and it belongs to the connection that started it: when
// that connection closes the tunnel comes down. See docs/ARCHITECTURE-GUI.md,
// "Liveness: no window, no tunnel". The component could keep running without a
// window — it does its own device calls — so this is a rule it enforces rather
// than a consequence of anything.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/encedo/encedo-wg-hsm/internal/ipc"
	"github.com/encedo/encedo-wg-hsm/internal/session"
)

// Tunnel is what the daemon drives, reduced to the two things it needs: run
// until told otherwise, and take a new token part way through.
type Tunnel interface {
	// Run holds the tunnel up until ctx is cancelled or it ends on its own,
	// emitting a snapshot whenever anything changes.
	Run(ctx context.Context, emit func(ipc.Event)) error

	// Refresh replaces the token the tunnel acts with. Renewal is a human act
	// and the human is at the window.
	Refresh(token string) error
}

// Open builds a tunnel from a start request, or refuses it.
//
// A function rather than an import: internal/tunnel carries netlink and the
// patched wireguard-go, and a package that only needs to accept connections and
// keep one session straight has no business inheriting either. The command wires
// the real one in; a test wires in something that does nothing.
type Open func(ctx context.Context, req ipc.Request) (Tunnel, error)

// Server is the listening half. Zero values are not useful: Open is required.
type Server struct {
	Open  Open
	Build ipc.Build

	// Log is where anything worth a system journal goes. Optional.
	Log func(string)

	mu      sync.Mutex
	running bool
	owner   Principal // who started the tunnel that is running
	cancel  context.CancelFunc
	tun     Tunnel
}

func (s *Server) log(format string, args ...any) {
	if s.Log != nil {
		s.Log(fmt.Sprintf(format, args...))
	}
}

// Serve accepts until the listener is closed. Connections are handled
// concurrently: a second window must be told that a tunnel is already running,
// and a daemon that accepted one at a time would leave it waiting instead.
func (s *Server) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handle(c)
	}
}

// handle runs one connection to its end, and takes the tunnel down with it.
func (s *Server) handle(c net.Conn) {
	defer c.Close()

	who, err := peerPrincipal(c)
	if err != nil {
		// Not knowing who is asking is a refusal, not a detail to shrug at:
		// every rule below is written in terms of the answer.
		s.log("refusing a connection whose owner could not be determined: %v", err)
		_ = ipc.WriteMsg(c, refusal(session.KindAuth, "this connection's owner could not be determined"))
		return
	}

	// Whatever this connection started dies with it, and only what it started.
	started := false
	defer func() {
		if started {
			s.stop(who)
		}
	}()

	for {
		raw, err := ipc.ReadMsg(c)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				s.log("connection from %s ended: %v", who, err)
			}
			return
		}
		req, err := ipc.DecodeRequest(raw)
		if err != nil {
			_ = ipc.WriteMsg(c, refusal(session.KindDevice, "unreadable request: "+err.Error()))
			continue
		}
		if err := req.Validate(); err != nil {
			_ = ipc.WriteMsg(c, refusal(session.KindDevice, err.Error()))
			continue
		}

		switch req.Op {
		case ipc.OpStart:
			if err := s.start(c, who, req); err != nil {
				_ = ipc.WriteMsg(c, refusalFrom(err))
				continue
			}
			started = true
			_ = ipc.WriteMsg(c, ipc.Msg{Type: ipc.TypeReply, Reply: &ipc.Reply{OK: true, Build: &s.Build}})

		case ipc.OpStop:
			s.stop(who)
			started = false
			_ = ipc.WriteMsg(c, ipc.Msg{Type: ipc.TypeReply, Reply: &ipc.Reply{OK: true}})

		case ipc.OpRefresh:
			if err := s.refresh(who, req.Token); err != nil {
				_ = ipc.WriteMsg(c, refusalFrom(err))
				continue
			}
			_ = ipc.WriteMsg(c, ipc.Msg{Type: ipc.TypeReply, Reply: &ipc.Reply{OK: true}})
		}
	}
}

func (s *Server) start(c net.Conn, who Principal, req ipc.Request) error {
	if !s.Build.Matches(req.Build) {
		// Named on both sides, because the usual mismatch is a record dialect
		// and its natural symptom is a MAC failure — which reads as somebody
		// having tampered with a configuration rather than as two builds that
		// disagree.
		return session.Fail(session.KindDevice,
			"this component is %s and the window is %s; they cannot drive each other",
			s.Build, req.Build)
	}

	s.mu.Lock()
	if s.running {
		owner := s.owner
		s.mu.Unlock()
		if owner != who {
			return session.Fail(session.KindDevice, "a tunnel is already running, and it belongs to another user")
		}
		return session.Fail(session.KindDevice, "a tunnel is already running")
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.running, s.owner, s.cancel = true, who, cancel
	s.mu.Unlock()

	t, err := s.Open(ctx, req)
	if err != nil {
		cancel()
		s.clear()
		return err
	}

	s.mu.Lock()
	s.tun = t
	s.mu.Unlock()

	go func() {
		defer cancel()
		emit := func(e ipc.Event) { _ = ipc.WriteMsg(c, ipc.Msg{Type: ipc.TypeEvent, Event: &e}) }
		if err := t.Run(ctx, emit); err != nil {
			s.log("tunnel ended: %v", err)
			emit(ipc.Event{State: "ended", Notice: err.Error()})
		}
		s.clear()
	}()
	return nil
}

// stop takes the tunnel down, if this caller is the one entitled to.
func (s *Server) stop(who Principal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running || s.owner != who {
		return
	}
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *Server) refresh(who Principal, token string) error {
	s.mu.Lock()
	running, owner := s.running, s.owner
	s.mu.Unlock()
	if !running {
		return session.Fail(session.KindDevice, "no tunnel is running")
	}
	if owner != who {
		return session.Fail(session.KindDevice, "that tunnel belongs to another user")
	}

	s.mu.Lock()
	t := s.tun
	s.mu.Unlock()
	if t == nil {
		return session.Fail(session.KindDevice, "no tunnel is running")
	}
	return t.Refresh(token)
}

func (s *Server) clear() {
	s.mu.Lock()
	s.running, s.cancel, s.tun = false, nil, nil
	s.mu.Unlock()
}

// Running reports whether a tunnel is up. For a status command, and for tests.
func (s *Server) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

func refusal(kind session.Kind, msg string) ipc.Msg {
	return ipc.Msg{Type: ipc.TypeReply, Reply: &ipc.Reply{OK: false, Err: msg, Kind: kind.String()}}
}

func refusalFrom(err error) ipc.Msg {
	return refusal(session.KindOf(err), err.Error())
}
