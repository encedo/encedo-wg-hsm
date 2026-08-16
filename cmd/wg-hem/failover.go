package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/encedo/encedo-wg-hsm/internal/config"
	"github.com/encedo/encedo-wg-hsm/internal/tunnel"
)

// repromptPeer asks which peer to try next after one stopped answering (section 6.4).
// The failed peer stays on the list - an endpoint can come back, and the
// operator may know something this process does not - but it is marked, and the
// suggestion moves on to the next one in the stored order.
func repromptPeer(tree *config.Tree, failed *config.Peer) (*config.Peer, error) {
	suggestion := 1
	for i := range tree.Peers {
		if tree.Peers[i].KID == failed.KID {
			suggestion = (i+1)%len(tree.Peers) + 1
			break
		}
	}

	fmt.Fprintf(os.Stderr, "\nPeer %q (%s) is not responding after %s.\n",
		failed.Label, failed.Endpoint.String(), tunnel.FailoverTimeout)
	fmt.Fprintln(os.Stderr, "Peers in this configuration:")
	for i, p := range tree.Peers {
		mark := " "
		if p.KID == failed.KID {
			mark = "!"
		}
		fmt.Fprintf(os.Stderr, "  %s %d) %-20s %s\n", mark, i+1, p.Label, p.Endpoint.String())
	}
	fmt.Fprintf(os.Stderr, "Connect to [%d]: ", suggestion)

	line, err := readLine()
	if err != nil {
		// No terminal to ask, or the operator closed it. There is no answer to
		// guess at here: a wrong peer is a tunnel to the wrong place.
		return nil, failf(exitNetwork, "peer %q is not responding and there is nobody to ask: %w",
			failed.Label, err)
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return &tree.Peers[suggestion-1], nil
	}
	n, err := strconv.Atoi(line)
	if err != nil || n < 1 || n > len(tree.Peers) {
		return nil, failf(exitUsage, "%q is not one of the %d peers offered", line, len(tree.Peers))
	}
	return &tree.Peers[n-1], nil
}
