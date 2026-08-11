//go:build !descr64

package descr

// Size is the exact length of an encoded record, fixed by the capacity of the
// device's descr field.
//
// The record length is not a free choice: the canonical message that the MAC
// covers includes each record at its full padded length (§4), so a tree written
// by a build with one Size cannot be verified by a build with another. The
// binary has to match the firmware it talks to.
const Size = 128
