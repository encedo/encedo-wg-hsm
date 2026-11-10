package descr

// Size is the exact length of an encoded record, fixed by the capacity of the
// device's descr field (128 bytes since firmware 1.3).
//
// The record length is not a free choice: the canonical message that the MAC
// covers includes each record at its full padded length (section 4), so a tree
// written with another length - by a build for the 64-byte firmware before
// 1.3 - cannot be verified, and has to be provisioned again.
const Size = 128
