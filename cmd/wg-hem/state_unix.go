//go:build !windows

package main

// stateDeniedAdvice is what to do about a state file that cannot be read.
//
// The run directory is shared by group — that is how a client without root
// writes there at all — so the answer is almost always that the person is not
// in it yet, and membership is per login session rather than immediate.
const stateDeniedAdvice = `That directory is shared by group. Add yourself to it and log in again:
  sudo adduser "$USER" wireguard`
