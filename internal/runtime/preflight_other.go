//go:build !linux

package runtime

// Preflight has nothing to check on these platforms yet.
//
// macOS and Windows both need elevation rather than a capability, and neither
// has an equivalent of setcap: there is no way to grant this one binary the one
// permission it wants. That is what a privileged helper is for, and until one
// exists the honest answer is that the client is run elevated. Saying so before
// the tunnel starts would only repeat what the operating system already says
// when it refuses.
func Preflight() error { return nil }
