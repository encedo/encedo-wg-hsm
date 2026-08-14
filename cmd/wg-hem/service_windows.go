package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// The privileged component on Windows is a service, and it is a service for a
// reason that is not administrative tidiness.
//
// wireguard-go creates its UAPI pipe with the descriptor
// `O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)` — owner SYSTEM. Assigning
// SYSTEM as the owner of an object is not something an administrator may do, so
// an elevated console run gets as far as creating the adapter and completing a
// handshake and then fails at `ipc.UAPIListen` with "this security ID may not be
// assigned as the owner of this object". Measured on 2026-08-13.
//
// The account that can is LocalSystem, and the supported way to be LocalSystem
// is to be a service. That is the whole of why this file exists: everything
// answered from that pipe — `wg show`, `wg-hem status`, failover — is off until
// the component runs here.
//
// The Linux counterpart is packaging/linux/encedo-wg.service, and the two are
// deliberately alike in what they promise: nothing is brought up at boot. The
// service exists so that a person who opens the window does not have to be an
// administrator, not so that a tunnel exists without one.

const (
	serviceName = "encedo-wg"
	serviceDesc = "Encedo WireGuard tunnels for a graphical client"
)

func platformCommand(name string, args []string) (bool, error) {
	if name != "service" {
		return false, nil
	}
	if len(args) == 0 {
		return true, failf(exitUsage, "%s", serviceUsage())
	}
	switch args[0] {
	case "install":
		return true, serviceInstall()
	case "uninstall":
		return true, serviceUninstall()
	case "start":
		return true, serviceControl("start")
	case "stop":
		return true, serviceControl("stop")
	case "run":
		// What the Service Control Manager invokes. Runnable by hand as well,
		// which is how the handler is debugged without an installation.
		return true, serviceRun()
	default:
		return true, failf(exitUsage, "unknown service command %q\n\n%s", args[0], serviceUsage())
	}
}

func serviceUsage() string {
	return `wg-hem service — register the privileged component with Windows

  wg-hem service install     register it, running as LocalSystem
  wg-hem service uninstall   remove the registration
  wg-hem service start|stop  ask the service manager to run or halt it
  wg-hem service run         run the handler in this process (what the manager does)

install and uninstall need an elevated prompt. The service runs as LocalSystem
because the UAPI pipe wireguard-go creates is owned by SYSTEM and no other
account may create it.`
}

// serviceInstall registers this executable, at the path it is currently at.
//
// Not a copy into Program Files: placing files is an installer's job, and a
// service registered against a path that something else is responsible for
// filling is a service that fails at boot with a message about a missing file.
// Whoever runs this has already put the binary where they want it.
func serviceInstall() error {
	exe, err := os.Executable()
	if err != nil {
		return failf(exitDevice, "finding this executable: %w", err)
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return failf(exitDevice, "resolving %s: %w", exe, err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return failf(exitUsage, "reaching the service manager (is this prompt elevated?): %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return failf(exitUsage, "%s is already installed — uninstall it first", serviceName)
	}

	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName: serviceDesc,
		Description: serviceDesc,
		// Manual, not automatic: see the note at the top of this file. A tunnel
		// needs a window, and a window is somebody sitting down.
		StartType: mgr.StartManual,
		// LocalSystem is the default for a service with no account named, and
		// it is named here anyway because it is the requirement rather than the
		// default — see the descriptor quoted above.
		ServiceStartName: "LocalSystem",
	}, "service", "run")
	if err != nil {
		return failf(exitDevice, "registering %s: %w", serviceName, err)
	}
	defer s.Close()

	// The event log is where a service says anything at all: it has no terminal,
	// and a failure with nowhere to go is a service that "just does not start".
	if err := eventlog.InstallAsEventCreate(serviceName,
		eventlog.Error|eventlog.Warning|eventlog.Info); err != nil &&
		!strings.Contains(err.Error(), "already exists") {
		s.Delete()
		return failf(exitDevice, "registering the event source: %w", err)
	}

	fmt.Printf("%s installed, running as LocalSystem, started on demand.\n", serviceName)
	fmt.Printf("Start it with:  wg-hem service start\n")
	return nil
}

func serviceUninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return failf(exitUsage, "reaching the service manager (is this prompt elevated?): %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return failf(exitUsage, "%s is not installed", serviceName)
	}
	defer s.Close()

	if err := s.Delete(); err != nil {
		return failf(exitDevice, "removing %s: %w", serviceName, err)
	}
	// Not fatal. The service is gone either way, and refusing to finish over a
	// leftover log source would leave the caller with neither.
	if err := eventlog.Remove(serviceName); err != nil {
		fmt.Fprintf(os.Stderr, "note: the event source could not be removed: %v\n", err)
	}
	fmt.Printf("%s removed.\n", serviceName)
	return nil
}

func serviceControl(what string) error {
	m, err := mgr.Connect()
	if err != nil {
		return failf(exitUsage, "reaching the service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return failf(exitUsage, "%s is not installed", serviceName)
	}
	defer s.Close()

	switch what {
	case "start":
		if err := s.Start(); err != nil {
			return failf(exitDevice, "starting %s: %w", serviceName, err)
		}
	case "stop":
		if _, err := s.Control(svc.Stop); err != nil {
			return failf(exitDevice, "stopping %s: %w", serviceName, err)
		}
	}
	return nil
}

// handler is the service as the manager sees it: a state machine that must
// answer promptly, with the actual work on another goroutine.
type handler struct {
	log *eventlog.Log
}

func (h *handler) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	s <- svc.Status{State: svc.StartPending}

	// The daemon holds its goroutine for the life of the service, so it runs on
	// one of its own and reports here if it gives up. cmdDaemon is the same
	// entry point the Linux unit runs, with the same flags: whatever this
	// service does, `wg-hem daemon` on a console does too, which is what makes
	// the thing debuggable without a service manager in the way.
	failed := make(chan error, 1)
	go func() { failed <- cmdDaemon(nil) }()

	s <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case err := <-failed:
			if err != nil {
				h.say(eventlog.Error, fmt.Sprintf("the component stopped: %v", err))
				s <- svc.Status{State: svc.StopPending}
				// Non-zero tells the manager this was a failure rather than a
				// stop, which is what makes any configured recovery apply.
				return false, 1
			}
			s <- svc.Status{State: svc.StopPending}
			return false, 0

		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				// Closing the listener ends every connection on it, and a
				// connection ending takes its tunnel down — the same rule the
				// window relies on when it is closed. Nothing else to unwind.
				s <- svc.Status{State: svc.StopPending}
				return false, 0
			default:
				h.say(eventlog.Warning, fmt.Sprintf("unexpected control request %d", c.Cmd))
			}
		}
	}
}

func (h *handler) say(level uint16, msg string) {
	if h.log == nil {
		return
	}
	switch level {
	case eventlog.Error:
		_ = h.log.Error(1, msg)
	case eventlog.Warning:
		_ = h.log.Warning(1, msg)
	default:
		_ = h.log.Info(1, msg)
	}
}

func serviceRun() error {
	// IsWindowsService and not IsAnInteractiveSession, which is deprecated and
	// answers a different question badly: it asks whether the token is in the
	// Interactive group, which a service configured to interact with the desktop
	// also is.
	asService, err := svc.IsWindowsService()
	if err != nil {
		return failf(exitDevice, "asking whether this is a service: %w", err)
	}

	h := &handler{}
	if l, err := eventlog.Open(serviceName); err == nil {
		h.log = l
		defer l.Close()
	}

	// Run by hand rather than by the manager: do the work directly instead of
	// waiting for control requests that will never arrive. This is how the
	// component is debugged on a console, elevated, before it is installed —
	// and it will fail at the UAPI pipe there, which is the point of the note
	// at the top of this file.
	if !asService {
		fmt.Fprintf(os.Stderr,
			"note: not running as a service, so this is not LocalSystem and the UAPI pipe will refuse.\n")
		return cmdDaemon(nil)
	}

	if err := svc.Run(serviceName, h); err != nil {
		h.say(eventlog.Error, fmt.Sprintf("the service could not run: %v", err))
		return failf(exitDevice, "running as a service: %w", err)
	}
	return nil
}
