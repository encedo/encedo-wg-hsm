package main

import (
	"context"
	"time"
)

// State is what the window shows. The module being present is a state of its
// own rather than a disabled button, because for this product the identity is a
// physical object and "plug in your key" is a thing a person can act on.
type State int

const (
	NoModule State = iota
	Ready
	Connecting
	Connected
	Disconnecting
	Ended
)

func (s State) String() string {
	switch s {
	case NoModule:
		return "no module"
	case Ready:
		return "ready"
	case Connecting:
		return "connecting"
	case Connected:
		return "connected"
	case Disconnecting:
		return "disconnecting"
	default:
		return "ended"
	}
}

// Event is everything the interface knows. It is a snapshot rather than a delta
// so a late subscriber cannot end up displaying a state that was never true.
type Event struct {
	State State
	Peer  string

	// Addrs is what the tunnel's interface was given, in CIDR form. Usually one;
	// the window shows the first and says how many more there are, because the
	// question this answers — "what is my address on the VPN" — has one answer
	// in every configuration anybody has written so far.
	Addrs []string

	// HEM is where the module is being looked for. It belongs in the state
	// rather than in a settings dialogue: a personal appliance answers at a
	// fixed address on its own link and nobody ever changes it, while an
	// enterprise one is somewhere on the network and cannot be guessed. The
	// window has to be able to say which it is looking at, or "no module" is
	// indistinguishable from "wrong address".
	HEM string

	// ExpiresAt is read from the token, never computed from the requested
	// session length. A soak run on 2026-08-11 asked for eight hours and the
	// session ended after seven and a half; a countdown derived from the request
	// would have been wrong by twenty-seven minutes, and wrong in the direction
	// that strands somebody mid-afternoon.
	ExpiresAt time.Time

	LastHandshake time.Time
	Rx, Tx        uint64

	// Reach is why the device did not answer, when it did not. Empty otherwise.
	//
	// It is deliberately not a Notice: the presence check runs every three
	// seconds and a machine with nothing plugged in fails it forever, so this
	// would be an alert that never stops. It belongs in the advanced panel,
	// where somebody is already looking for a reason.
	Reach string

	// Notice carries something worth telling the user that is not an error —
	// failover moving to another peer, most of all.
	Notice string
	Err    error
}

// Session is the whole of what the interface drives. The skeleton runs against
// fakeSession; the real one arrives when the tunnel lifecycle moves out of
// cmd/wg-hem into internal/. That move is a separate change on main, and this
// interface is its specification: if the window only ever reads Events, then
// swapping the implementation should not touch a line of interface code.
type Session interface {
	// Connect starts the tunnel. The passphrase is passed rather than read,
	// because the thing doing the reading is a window now.
	Connect(ctx context.Context, passphrase []byte) error

	// Disconnect brings the tunnel down and leaves the session usable.
	Disconnect() error

	// Events emits a snapshot whenever anything changes. Closed by Close.
	Events() <-chan Event

	// Close ends the session for good. Closing the window calls this, which is
	// the whole architecture in one line: the window is the session, so nothing
	// holding a credential outlives it.
	Close() error
}
