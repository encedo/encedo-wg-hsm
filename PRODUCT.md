# wg-hsm — WireGuard with Hardware Key Protection

## The key that cannot be stolen

Every WireGuard deployment has a silent vulnerability: the private key sitting in a config file on disk. Root access, a backup leak, a misconfigured file permission, a cloud snapshot — any of these exposes the key permanently. Once stolen, past and future traffic can be decrypted. The device can be impersonated. There is no recovery short of rotating every peer.

**wg-hsm eliminates this attack surface entirely.** The private key is generated inside an **Encedo HEM** (Hardware Encryption Module) and never leaves it — not during provisioning, not during operation, not ever. WireGuard runs normally. The key does not.

---

## How it compares

### Standard WireGuard

| Property | Standard WireGuard | wg-hsm |
|---|---|---|
| Private key location | Plaintext in config file | Inside HEM, never exported |
| Peer public keys in config | Yes (base64 strings) | No — opaque KIDs only |
| Cryptographic material in config | Yes | **Zero** |
| Key extractable by root | Yes | No |
| Key survives device compromise | No | Yes |
| Config safe to store in git/CMDB | No | Yes |
| Audit trail for key usage | None | HEM logs every ECDH |
| Compatible with standard WG peers | — | Yes, fully |
| Requires hardware | No | An Encedo HEM |

### Commercial VPN appliances (Cisco, Palo Alto, Fortinet)

Enterprise VPN appliances offer TPM or secure enclave integration on their own hardware. The protection is real but the lock-in is total: proprietary protocols, proprietary hardware, five-figure licensing, and an attack surface that includes the vendor's firmware update pipeline.

wg-hsm gives you the same cryptographic guarantee on commodity Linux hardware, using the open WireGuard protocol, with peers that are standard WireGuard clients — phones, laptops, routers — with no changes required on their side.

### Soft HEM / PKCS#11 solutions

Software HSMs (SoftHSM, cloud KMS) keep the key out of the config file but not out of memory. A process dump, a hypervisor snapshot, or a side-channel attack can still recover the key material. Proper security requires hardware.

PKCS#11 integration with WireGuard does not exist in any mainline implementation. Existing attempts require kernel patches, custom builds, or abandoning WireGuard entirely for IPsec.

### Cloud KMS (AWS KMS, Google Cloud HEM, Azure Key Vault)

Cloud KMS protects keys from application-layer compromise but not from cloud provider access, subpoena, or insider threat. It also requires internet connectivity for every cryptographic operation, introduces latency on the handshake path, and creates a hard dependency on a third-party service for network connectivity — a circular dependency if your VPN is how you reach that cloud.

The Encedo HEM is on-premises or self-hosted. Your keys, your hardware, your network.

---

## Key advantages

### Hardware-rooted trust without complexity

The Encedo HEM ships in two models - EPA and PPA - which expose one identical REST API over TLS 1.3, so nothing here is written against either in particular. Integration is a network call, not a driver, not a kernel module, not a PKCS#11 shim. The wg-hsm client is pure Go, cross-compiled to any Linux target.

### Zero changes to your peers

The server running wg-hsm presents the same Curve25519 public key to the network. Peers are standard WireGuard — Android, iOS, Linux, Windows, MikroTik, anything. They need no modification, no special client, no knowledge that an HEM is involved.

### Separation of key custody and network operation

With wg-hsm you can provision keys in the HEM, hand the device to an operator, and know with certainty that the operator cannot extract the key. The operator can bring the VPN up, keep it running, and take it down — but they cannot compromise the key even with full system access.

This is the property that matters for:
- **Regulated industries** (finance, healthcare, government) where key custody must be demonstrably separated from system administration
- **Edge and OT deployments** where devices are physically accessible to untrusted parties
- **Managed security services** where the MSSP operates infrastructure on behalf of a client and must prove non-access to key material

### Zero cryptographic material in configuration

The wg-hsm config file contains no keys, no secrets, no cryptographic material of any kind — only opaque 32-character identifiers (KIDs) that reference keys stored in the HEM:

```ini
[Interface]
HEM_KID = <my-private-key-id>

[Peer]
HEM_KID = <peer-public-key-id>
```

This has consequences that go well beyond the key itself:

**The config file is safe to store anywhere.** It can be committed to git, stored in a CMDB, sent over email, included in a ticket, backed up to S3, or printed on paper. Leaking the config leaks nothing cryptographic. An attacker who obtains the config gains only the knowledge that two HEM key IDs are associated — they cannot derive, use, or impersonate either key.

**Backups are safe.** Automated backups of `/etc/wireguard/` no longer represent a key exposure risk. Snapshot-based backup systems, configuration management tools (Ansible, Puppet, Chef), and infrastructure-as-code repositories can include WireGuard configs without creating key custody problems.

**Peer identities are protected.** In standard WireGuard, the config file reveals the public keys of every peer — sufficient to identify devices on the network and correlate them across deployments. In wg-hsm with HEM-stored peer keys, the config reveals only opaque identifiers. The mapping from KID to actual device identity is maintained in the HEM, accessible only to authorized administrators.

**Separation of configuration management and key management.** Operators who manage network configuration (addresses, endpoints, routing) never need access to key material. Security administrators manage the HEM. The two roles are cleanly separated with no overlap — enforced by the system, not by policy.

**Compliance posture.** Regulations that require cryptographic key material to be stored in approved key management systems (FIPS 140-2, PCI-DSS, NIS2) can be satisfied without exemptions or compensating controls. The config file is not a key store — the HEM is.

### Graceful failure

If the HEM becomes unreachable and all retries are exhausted, wg-hsm brings the interface down cleanly rather than running a tunnel with a broken cryptographic state. Fail-closed by design.

### Audit

Every private key operation — every WireGuard handshake — is an ECDH call logged by the HEM. You get a hardware-attested record of when your VPN negotiated sessions, with whom, and whether the key was used. No software log can offer equivalent assurance.

---

## Threat model

| Threat | Standard WireGuard | wg-hsm |
|---|---|---|
| Attacker reads config file | Key compromised | No key in file — KIDs only |
| Config committed to git | Key exposed | Safe — no key material |
| Backup / snapshot leak | Key compromised | No key to leak |
| Attacker gets root shell | Key compromised | No key in memory |
| Physical access to device | Key compromised | Key in HEM, requires auth |
| Insider threat (sysadmin) | Key compromised | Key never accessible |
| Peer identity revealed via config | Yes (public key visible) | No — opaque KID only |
| HEM physically stolen | — | Requires PIN/auth, tamper-evident |

---

## Summary

wg-hsm is the only open-source solution that brings hardware key protection to WireGuard without modifying peers, without vendor lock-in, and without abandoning the simplicity that makes WireGuard worth using in the first place.

The private key is hardware. Everything else is standard.
