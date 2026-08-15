package main

// stateDeniedAdvice is what to do about a state file that cannot be read.
//
// There is no group to join here. The state file belongs to whoever ran the
// tunnel, and on this platform that is usually not the person asking: a tunnel
// the service started belongs to LocalSystem, because LocalSystem is the only
// account that may create the UAPI pipe wireguard-go asks for. So the file is
// unreadable for the same reason the tunnel works at all.
//
// Both remedies are named because which one applies depends on the ACL the file
// inherited, and the caller can try them in order faster than they can inspect
// it. Everything the state file holds is also on screen in the window, which is
// the answer for anybody who is not debugging.
const stateDeniedAdvice = `That state file belongs to whoever started the tunnel, which for a tunnel the
service started is LocalSystem. Read it as the same account:
  from an elevated prompt, or
  psexec -s wg-hem status`
