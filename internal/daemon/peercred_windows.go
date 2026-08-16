package daemon

import (
	"fmt"
	"net"
	"runtime"

	"golang.org/x/sys/windows"
)

// peerPrincipal asks Windows who is on the other end of the pipe, by briefly
// becoming them.
//
// This is the part of the access control that cannot be forged, and the choice
// of mechanism is the whole of it. A named pipe will also tell you the client's
// process id, through GetNamedPipeClientProcessId, and that is the obvious call
// and the wrong one: Project Zero published a technique for spoofing it, so the
// number identifies a process the caller nominated rather than the process
// calling. It is also not in x/sys/windows, so taking it would have meant a
// direct kernel32 call for an answer not worth having.
//
// Impersonation asks the kernel instead. ImpersonateNamedPipeClient puts the
// client's access token on this thread, the thread token names the account it
// was issued to, and nothing the client sends is involved.
//
// The counterpart on Linux is SO_PEERCRED, and both are the same idea: the
// pipe's security descriptor decides who may connect at all - that is the
// primary control, set when the pipe is created - and this answers the question
// that remains once somebody has, which is which account, so that a tunnel can
// belong to the person who started it.
func peerPrincipal(c net.Conn) (Principal, error) {
	// The handle, not the connection. namedpipe's conn type is unexported and
	// exposes the handle through a method, so this is the only way to ask for
	// it, and it holds for anything else that offers the same method.
	h, ok := c.(interface{ Handle() windows.Handle })
	if !ok {
		return Anonymous, fmt.Errorf("not a named pipe: %T", c)
	}

	// Impersonation is a property of the OS thread, not of the goroutine, so the
	// goroutine has to stay on one for as long as it lasts. Without this the
	// runtime may move it after the impersonation and before the token is read,
	// and the token read would be of whatever thread it landed on - which is the
	// service's own, LocalSystem, and would answer every caller with the same
	// wrong and highly privileged identity.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := impersonateNamedPipeClient(h.Handle()); err != nil {
		return Anonymous, fmt.Errorf("impersonating the caller: %w", err)
	}
	// Deferred, and its failure is not survivable: a thread left impersonating
	// would hand the next caller the identity of this one. Unlocking the thread
	// while it still wears somebody else's token is what makes that possible, so
	// the panic is deliberate - the alternative is a silent authorisation bug.
	defer func() {
		if err := windows.RevertToSelf(); err != nil {
			panic("wg-hem: could not stop impersonating a caller: " + err.Error())
		}
	}()

	var token windows.Token
	// openAsSelf: the lookup itself is done as the service rather than as the
	// account just impersonated, which is what lets it succeed when the caller
	// is a low-privilege account that could not open its own token here.
	if err := windows.OpenThreadToken(windows.CurrentThread(),
		windows.TOKEN_QUERY, true, &token); err != nil {
		return Anonymous, fmt.Errorf("opening the caller's token: %w", err)
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil {
		return Anonymous, fmt.Errorf("reading the caller's account: %w", err)
	}
	sid := user.User.Sid.String()

	// A client chooses the impersonation level when it opens the pipe, and one
	// that opens it anonymously - which is the default in every convenience
	// wrapper worth naming, including go-winio's DialPipeContext - gets this
	// answer for everybody. Accepting it would give every such caller the same
	// principal, so any of them could stop any other's tunnel, and both ends
	// would look correct throughout.
	//
	// The window asks for identification explicitly. Anything that did not is
	// either mistaken or curious, and both are told rather than accommodated.
	if sid == anonymousLogonSID {
		return Anonymous, fmt.Errorf(
			"the caller connected anonymously, so it cannot be identified - " +
				"open the pipe at SECURITY_IDENTIFICATION or above")
	}
	return Principal("sid:" + sid), nil
}

// anonymousLogonSID is S-1-5-7, what an anonymous token reports as its user.
const anonymousLogonSID = "S-1-5-7"

// impersonateNamedPipeClient is in advapi32 and not in x/sys/windows, so it is
// declared here rather than waited for.
var (
	advapi32                       = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateNamedPipeClient = advapi32.NewProc("ImpersonateNamedPipeClient")
)

func impersonateNamedPipeClient(pipe windows.Handle) error {
	r, _, err := procImpersonateNamedPipeClient.Call(uintptr(pipe))
	if r == 0 {
		return err
	}
	return nil
}
