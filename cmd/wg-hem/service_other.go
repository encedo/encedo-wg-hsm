//go:build !windows

package main

// platformCommand is where a platform puts the verbs only it has. There are
// none here: on Linux the equivalent work — registering the service, creating
// its user, granting the capability — belongs to the package, which does it at
// install time and is the thing an administrator actually runs.
func platformCommand(string, []string) (bool, error) { return false, nil }
