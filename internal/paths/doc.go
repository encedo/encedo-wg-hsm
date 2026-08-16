// Package paths holds the one filesystem location both halves of this client
// need to agree on, and nothing else.
//
// It is a package for a single constant because of what that constant used to
// cost. The run directory lived in internal/runtime, next to netlink, the tunnel
// device and the platform code - so anything that wanted to know where a state
// file goes had to import all of it. A window that only reads which tunnels are
// running would have pulled in the patched wireguard-go checkout, which is
// generated at build time and would have ended the graphical client's ability to
// be built on its own.
//
// Nothing here imports anything of ours. That is the point: it is a leaf, so it
// can be depended on from either side of the privilege boundary without
// dragging the other side across it.
package paths
