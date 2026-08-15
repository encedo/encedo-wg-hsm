package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/encedo/encedo-wg-hsm/internal/ipc"
)

// cmdProbe asks a running component two questions and prints both answers.
//
// It exists because those two are the ones that fail quietly. A build mismatch
// is caught at OpStart and named on both sides — but only after somebody has
// typed a passphrase, which is a long way to walk to be told the halves do not
// match. And the caller's identity is the whole of the authorisation on this
// channel, computed from the connection rather than from anything sent, so
// neither side would notice it being wrong: on Windows a caller who connects at
// the wrong impersonation level is reported as ANONYMOUS LOGON, and everything
// still looks like it is working until two people share a principal.
//
// Nothing here needs a device, a passphrase or a tunnel, which is the point. It
// is the one thing that can be run against a freshly installed service to find
// out whether the channel works at all.
func cmdProbe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	sock := fs.String("socket", defaultSocket(), controlFlagUsage)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `wg-hem probe — ask the privileged component who it thinks you are

  wg-hem probe [--socket PATH]

Connects, asks, prints and leaves. It carries no token, starts nothing and
changes nothing, so it is safe against a component with a tunnel up.

Two things come back: the build the component is, to compare with this one, and
the account it identified this connection as. That identity is what decides
whose tunnel is whose, so it is worth seeing before trusting it.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return failf(exitUsage, "%w", err)
	}

	conn, err := dialControl(*sock)
	if err != nil {
		return failf(exitDevice, "the component is not answering on %s: %w\n"+
			"Is the service running?", *sock, err)
	}
	defer conn.Close()

	if err := ipc.WriteMsg(conn, ipc.Request{Op: ipc.OpWhoami, Build: ipc.Current()}); err != nil {
		return failf(exitDevice, "asking: %w", err)
	}

	raw, err := ipc.ReadMsg(conn)
	if err != nil {
		return failf(exitDevice, "reading the answer: %w", err)
	}
	m, err := ipc.DecodeMsg(raw)
	if err != nil {
		return failf(exitDevice, "the answer did not decode: %w", err)
	}
	if m.Type != ipc.TypeReply || m.Reply == nil {
		return failf(exitDevice, "expected a reply and got %q", m.Type)
	}
	if !m.Reply.OK {
		// A refusal is an answer too, and on Windows the likeliest one is worth
		// arriving already explained: the component refuses a caller it cannot
		// identify, and a caller it cannot identify is usually one that opened
		// the pipe anonymously.
		return failf(exitDevice, "the component refused: %s", m.Reply.Err)
	}

	fmt.Printf("socket %s\n", *sock)
	fmt.Printf("component %s\n", buildOf(m.Reply.Build))
	fmt.Printf("this %s\n", ipc.Current())
	fmt.Printf("identified-as %s\n", dashIf(m.Reply.Who))

	// Said rather than left to be noticed. The two halves refuse each other at
	// OpStart, so a mismatch found here is the same refusal arriving early and
	// cheaply, in the one place somebody is already looking at both numbers.
	if m.Reply.Build != nil && !m.Reply.Build.Matches(ipc.Current()) {
		fmt.Printf("\nThese two will refuse each other: the releases or the record\n" +
			"sizes differ. Build both halves from one clean tree.\n")
		return failf(exitUsage, "build mismatch")
	}
	return nil
}

func buildOf(b *ipc.Build) string {
	if b == nil {
		return "—"
	}
	return b.String()
}

func dashIf(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
