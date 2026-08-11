module github.com/encedo/encedo-wg-hsm

go 1.26.5

require (
	github.com/encedo/hem-sdk-go v0.0.0
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/crypto v0.37.0
	golang.org/x/term v0.31.0
	golang.zx2c4.com/wireguard v0.0.0-00010101000000-000000000000
)

require (
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

replace golang.zx2c4.com/wireguard => ./wireguard-go

// The SDK is a git submodule, so the build uses the checked-out commit rather
// than whatever the module proxy last published.
replace github.com/encedo/hem-sdk-go => ./hem-sdk-go
