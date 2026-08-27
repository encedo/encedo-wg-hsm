package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/encedo/encedo-wg-hsm/internal/wgconf"
)

// cmdImport provisions the device from an ordinary WireGuard client
// configuration - the file somebody is handed today, with a private key in it.
//
// What it does not do is carry that key across, and this is the whole point
// rather than a limitation. The device generates keys and never accepts one; a
// private key that has sat in a text file is already out, and moving it into a
// module afterwards would be pretending otherwise. So the identity is new, and
// the file's own PrivateKey line is read only far enough to be ignored.
//
// The consequence is the thing to be clear about with whoever runs this: the
// tunnel will not come up until the server is told the new public key. That is
// why the address is printed beside it. A server's configuration lists peers by
// key and allowed address, so the address is what an administrator can match a
// person against, and the key is what they replace.
func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	name := fs.String("name", "", "label for the peer, which a .conf file does not carry (prompted for if absent)")
	dryRun := fs.Bool("dry-run", false, "print the equivalent provision command and stop")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: wg-hem import <file.conf> [flags] [-- provision flags]

Reads a WireGuard client configuration and writes it into the HEM as a
configuration of this client's own: the addresses, the DNS servers, the MTU, and
the peer.

The private key in the file is discarded. This client's key is generated inside
the module and cannot leave it, so the imported tunnel has a new identity - and
will not connect until whoever runs the server replaces the old public key with
the one printed here. The address is printed with it, because that is what an
administrator can match a person against.

Anything after -- is passed to provision unchanged, so its flags are available:

  wg-hem import client.conf -- -session 8 -label "laptop"

Flags:
`)
		fs.PrintDefaults()
	}
	// The file is pulled out before the flags are parsed, because Go's flag
	// package stops at the first argument that is not a flag - so
	// `import file.conf -name x` would parse nothing and then ask for a name it
	// had been given. Both orders work now, which is what anybody would expect
	// of a command whose first argument is a file.
	ours, passthrough := splitAtDoubleDash(args)
	path, ours := takeFirstBareArg(ours)
	if path == "" {
		fs.Usage()
		return failf(exitUsage, "which file?")
	}
	if err := fs.Parse(ours); err != nil {
		return &exitError{code: exitUsage, err: err}
	}
	if extra := fs.Args(); len(extra) > 0 {
		return failf(exitUsage, "unexpected argument %q; flags for provision go after --", extra[0])
	}

	conf, err := wgconf.ParseFile(path)
	if err != nil {
		return failf(exitUsage, "%s: %w", path, err)
	}

	label := strings.TrimSpace(*name)
	if label == "" {
		// A .conf has nowhere to put a name, and the peer is about to become a
		// record somebody will read back in `wg-hem status` and choose between
		// during failover. "peer 1" would be a name that helps nobody.
		label, err = askPeerName()
		if err != nil {
			return failf(exitUsage, "%w", err)
		}
	}

	argv, err := conf.ProvisionArgs(label)
	if err != nil {
		return failf(exitUsage, "%s: %w", path, err)
	}
	argv = append(argv, passthrough...)

	if *dryRun {
		fmt.Println("wg-hem provision " + strings.Join(quoteAll(argv), " "))
		return nil
	}

	// Through provision rather than beside it. Everything after this point -
	// validating, generating the identity, importing the peer key, writing the
	// records, the MAC over them, and reading it back to verify - is the same
	// work with the same failure modes, and a second copy of it would be a
	// second thing to keep correct.
	if err := cmdProvision(argv); err != nil {
		return err
	}

	// provision has already printed the block to paste, so this adds only what
	// is true of a migration and not of a first provisioning: there is an entry
	// on the server already, the old key in the file is now dead, and nothing
	// works until somebody changes that one line.
	fmt.Fprintln(os.Stderr, "Imported from "+path+".")
	fmt.Fprintln(os.Stderr, "The peer entry above replaces the one this person already has: same")
	fmt.Fprintln(os.Stderr, "address, new PublicKey. Until the server is changed the tunnel will not")
	fmt.Fprintln(os.Stderr, "come up - the old private key stayed in the file and is not the one in")
	fmt.Fprintln(os.Stderr, "the module.")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "The file itself is untouched. Delete it once the tunnel works: the key")
	fmt.Fprintln(os.Stderr, "in it still opens whatever it opened before this ran.")
	return nil
}

// splitAtDoubleDash separates this command's own arguments from the ones meant
// for provision. Everything after the first -- belongs to provision, untouched.
func splitAtDoubleDash(args []string) (ours, theirs []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

// takeFirstBareArg removes and returns the first argument that is not a flag,
// leaving the rest in order.
//
// It does not try to understand which flags take values, because none of this
// command's do: -name is the only one with an argument and it is written
// -name=x or -name x - and in the second form the value would be taken as the
// file. So -name is the one case that is looked for by name.
func takeFirstBareArg(args []string) (string, []string) {
	rest := make([]string, 0, len(args))
	found := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if found == "" && !strings.HasPrefix(a, "-") {
			found = a
			continue
		}
		rest = append(rest, a)
		if a == "-name" || a == "--name" {
			// Its value follows and is not the file.
			if i+1 < len(args) {
				i++
				rest = append(rest, args[i])
			}
		}
	}
	return found, rest
}

// askPeerName reads a name for the peer, since the file has nowhere to carry
// one and the records are read by people afterwards.
func askPeerName() (string, error) {
	fmt.Fprint(os.Stderr, "Name for this peer (it is what `wg-hem status` will show): ")
	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("no name given")
	}
	name := strings.TrimSpace(sc.Text())
	if name == "" {
		return "", fmt.Errorf("no name given; pass -name to supply one without being asked")
	}
	if strings.ContainsAny(name, ",=") {
		// The peer specification provision takes is comma-separated key=value,
		// so either character in a name would split it into something else.
		return "", fmt.Errorf("a name cannot contain a comma or an equals sign")
	}
	return name, nil
}

// quoteAll makes the dry run's output something that can be pasted back.
func quoteAll(argv []string) []string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if strings.ContainsAny(a, " \t\"'") {
			out[i] = strconv.Quote(a)
		} else {
			out[i] = a
		}
	}
	return out
}
