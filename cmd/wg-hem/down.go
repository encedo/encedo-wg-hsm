package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"
	"time"

	rt "github.com/encedo/encedo-wg-hsm/internal/runtime"
)

// downTimeout is how long to wait for the owning process to finish its own
// teardown before taking the interface down from here. It is generous on
// purpose: that teardown reverts DNS and takes back the routing exceptions, and
// doing it properly matters more than doing it quickly.
//
// A variable so tests need not wait it out.
var downTimeout = 10 * time.Second

// signalProcess and takeDownInterface are the two things `down` does to the
// world. They are variables so the decision around them can be tested without a
// second process or a tunnel device.
var (
	signalProcess = func(pid int, sig syscall.Signal) error {
		proc, err := os.FindProcess(pid)
		if err != nil {
			return err
		}
		return proc.Signal(sig)
	}
	takeDownInterface = rt.Down
)

// cmdDown stops a running interface (section 10.2).
//
// The work is asked of the process that did it rather than done here. That
// process holds what has to be undone - the host routes pinned around the
// tunnel, the DNS the resolver was pointed at - and none of it is written down
// anywhere this command could rediscover it. Removing the interface from
// underneath it would take the tunnel down and leave both behind.
func cmdDown(args []string) error {
	fs := flag.NewFlagSet("down", flag.ContinueOnError)
	ifname := fs.String("interface", "wg0", "name of the tunnel interface")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "wg-hem down [--interface wg0]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return failf(exitUsage, "%w", err)
	}

	st, err := resolveState(*ifname, flagGiven(fs, "interface"))
	if err != nil {
		return err
	}
	// From here the interface is the one the state file records. On macOS that
	// is not the name the caller asked for, and the routes belong to the former.
	name := st.Interface

	if err := signalProcess(st.PID, syscall.SIGTERM); err == nil {
		if waitGone(name, st.PID) {
			fmt.Fprintf(os.Stderr, "Interface %s is down.\n", name)
			return nil
		}
		fmt.Fprintf(os.Stderr,
			"WARNING: pid %d did not finish within %s; taking %s down from here.\n",
			st.PID, downTimeout, name)
	} else {
		fmt.Fprintf(os.Stderr, "No live wg-hem process for %s; removing the interface only.\n", name)
	}

	// Either there is no owning process or it will not go. The interface is
	// still ours to remove, and saying so is better than reporting success over
	// a live tunnel - but whatever that process would have undone stays undone,
	// routing exceptions and DNS included.
	err = takeDownInterface(name)
	removeState(name)
	if err != nil {
		return failf(exitDevice, "removing %s: %w", name, err)
	}
	fmt.Fprintf(os.Stderr, "Interface %s is down.\n", name)
	return nil
}

// waitGone reports whether the owning process finished its teardown, which it
// signals by removing its own state file. A pid that has gone without doing so
// also counts: there is nothing left to wait for.
func waitGone(ifname string, pid int) bool {
	deadline := time.Now().Add(downTimeout)
	for {
		if _, err := os.Stat(statePath(ifname)); os.IsNotExist(err) {
			return true
		}
		// Signal 0 performs the same existence and permission checks as a real
		// signal without delivering one.
		if signalProcess(pid, syscall.Signal(0)) != nil {
			removeState(ifname)
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}
