# Security policy

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private vulnerability reporting on
this repository: **Security → Report a vulnerability**. That opens a private
advisory visible only to the maintainers.

Please include the version or commit, your config (redacted as needed), and the
smallest reproduction you have. You will get an acknowledgement; a fix and a
published advisory follow once one exists.

## Scope

In scope — anything that lets an unauthorised source get a firewall grant, keeps
a grant open past its window, crashes or hangs the daemon from the network,
exhausts its memory, or escalates beyond its two capabilities:

- The packet decoder (`src/capture/parse.rs`) — IPv4/IPv6/VLAN/QinQ handling of
  hostile or truncated frames.
- The matcher (`src/matcher.rs`) — any way to get a door to complete without
  sending its sequence, or to make one source's traffic affect another's state.
- The firewall backends — command injection through `%IP%` substitution, or
  nftables set elements that outlive their timeout.
- The config parsers, including the classic `knockd.conf` compatibility path.
- The stats endpoint (`[stats] listen`).

## Out of scope: what port knocking is not

Port knocking is **obfuscation, not authentication**, and this daemon does not
pretend otherwise. The following are properties of the technique, documented
deliberately, and are not vulnerabilities in this implementation:

- **A knock sequence travels in the clear and is replayable.** Anyone on the path
  — a router, an ISP, a hypervisor, a compromised switch — can observe a sequence
  and replay it verbatim. Keep `seq_timeout` and grant TTLs short, and keep real
  authentication (SSH keys, mTLS, a VPN) behind the door.
- **A grant is scoped to a source IP**, so anything sharing that address (NAT,
  a corporate egress) shares the grant for its lifetime.
- **Sequences can be brute-forced** given enough traffic and time. The per-source
  rate limiter (`[matching] rate_limit`) raises the cost; it does not remove it.

Reports amounting to "the sequence can be sniffed" will be closed with a pointer
to this section.

## Running it safely

Use the shipped systemd unit (`packaging/systemd/knockd2.service`): a
`DynamicUser` with exactly `CAP_NET_RAW` and `CAP_NET_ADMIN` ambient, plus the
hardening sandbox. Do not run the daemon as root. Bind `[stats] listen` to
localhost or a trusted management interface — it exposes operational counters.
