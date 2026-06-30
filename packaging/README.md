# Packaging knock-daemon

## systemd (Linux)

[`systemd/knockd2.service`](systemd/knockd2.service) runs the daemon under
**capability-based privilege** rather than root. A port-knocking daemon needs
exactly two capabilities:

| Capability       | Why                                                              |
| ---------------- | --------------------------------------------------------------- |
| `CAP_NET_RAW`    | Open the packet-capture socket (AF_PACKET, or libpcap).         |
| `CAP_NET_ADMIN`  | Modify the firewall (nftables backend, or a privileged command).|

The unit grants those via `AmbientCapabilities` to a transient `DynamicUser`,
sets `NoNewPrivileges=yes`, and clamps everything else with a hardening block
(`ProtectSystem=strict`, syscall filter, `RestrictAddressFamilies`, …). The
ambient grant is inherited by the `nft`/`iptables` child the command backend may
exec, so those still work without the daemon being root.

### Install

Build a release binary (pick a capture backend) and drop the files in place:

```sh
# Pure-Rust capture, no libpcap dependency:
cargo build --release --features capture-afpacket
# …or libpcap-backed:
# cargo build --release --features capture-pcap

sudo install -Dm755 target/release/knockd2            /usr/local/bin/knockd2
sudo install -Dm644 packaging/systemd/knockd2.service /etc/systemd/system/knockd2.service
sudo install -Dm600 knockd.toml                       /etc/knock-daemon/knockd.toml

sudo systemctl daemon-reload
sudo systemctl enable --now knockd2
```

For the `nftables` backend, create the allow-set the config references (with a
`timeout` flag so kernel-side expiry works) and a rule that uses it, e.g.:

```nft
table inet filter {
    set knock_clients { type ipv4_addr; flags timeout; }
    chain input {
        type filter hook input priority 0;
        ip saddr @knock_clients tcp dport 22 accept
    }
}
```

### Verify the dropped privileges

```sh
systemctl show knockd2 -p User -p AmbientCapabilities
grep Cap /proc/"$(systemctl show -p MainPID --value knockd2)"/status
```

You should see only `cap_net_admin` and `cap_net_raw` in the effective set.

### Notes for the `command` backend

The hardening defaults assume the nftables backend or a local `nft`/`iptables`
command. If your `open_command`/`close_command` does something broader (reaches
the network, writes outside `/etc`, etc.) you may need to relax
`RestrictAddressFamilies`, `ProtectSystem`, or `MemoryDenyWriteExecute`. Prefer
the `nftables` backend where you can — it needs none of those loosened.
