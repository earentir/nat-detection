# NAT‑Detection

Portable **NAT / CG‑NAT / UDP‑blocking detector** written in pure Go.

* 🔍 Detects regular home NAT, carrier‑grade NAT, NAT66 / NPTv6 and outright UDP blocking.
* 🖥️ Single self‑hosted VM (IPv4 + IPv6) provides:
  * **STUN** (UDP 3478) – fast path, no external dependency
  * **who‑am‑I** (TCP 8080) – fallback when UDP is blocked
* 📦 Cross‑compiles to Linux, macOS and Windows with a one‑shot script.
* 🛡 Uses the Go `internal/` convention so helper code is importable only inside the repo.
* 🏷️ Embeds version / commit / date into every binary via `-ldflags`.

![diagram](https://raw.githubusercontent.com/earentir/nat-detection/assets/arch.svg)

---

## Repository layout

``` bash
nat-detection/
├── build.sh            ← cross‑compile helper
├── client/             ← `natcheck` CLI (binary)
├── server/
│   ├── stun/           ← `stun`  (UDP‑3478 daemon)
│   └── whoami/         ← `whoami` (TCP‑8080 daemon)
├── internal/
│   └── stun/           ← helper library (XOR‑MAPPED parsing)
├── tools/
│   └── asnlookup/      ← `asnlookup` CLI helper
├── go.work             ← multi‑module workspace (Go ≥ 1.18)
└── ...
```

---

## Quick start – pre‑built binaries

1. **Download** the latest release from the [GitHub releases page](../../releases).
2. Un‑zip. You’ll find a folder structure identical to `bin/<os>_<arch>/` shown below.
3. Skip straight to [Running the server](#running-the-server) and [Running the client](#running-the-client).

---

## Building everything yourself

### Prerequisites

* Go 1.18 or newer (tested with 1.24.1)
* `git` in your `PATH`
* `bash` (for the build script)

```bash
git clone https://github.com/earentir/nat-detection.git
cd nat-detection
./build.sh      # ~5 s on a modern machine
```

Output:

``` bash
./bin/
├── linux_amd64/
│   ├── natcheck  ─┐
│   ├── stun      ├─ built with CGO disabled, static
│   ├── whoami    └─ but version strings embedded
│   └── asnlookup
├── linux_arm64/ …
├── darwin_amd64/ …
├── darwin_arm64/ …
└── windows_amd64/
    └── *.exe
```

> **Tip** – add `bin/$(go env GOOS)_$(go env GOARCH)` to your shell `$PATH`
> if you often rebuild for your own host.

---

## Running the server

> You need exactly **one VM** with both a public IPv4 and IPv6 address.

### 1  Open the required ports

| proto | port | purpose           |
|-------|------|-------------------|
| UDP   | 3478 | STUN Binding      |
| TCP   | 8080 | who‑am‑I fallback |

```bash
# example on a Debian‑based distro using ufw
sudo ufw allow 3478/udp comment "STUN"
sudo ufw allow 8080/tcp comment "whoami"
```

### 2  Deploy the daemons

```bash
# copy the correct platform binaries from ./bin/ to /opt/nat/
scp bin/linux_amd64/stun   earentir@vm:/opt/nat/
scp bin/linux_amd64/whoami earentir@vm:/opt/nat/

ssh earentir@vm
sudo setcap cap_net_bind_service=+ep /opt/nat/stun   # allow <1024 without root
sudo tee /etc/systemd/system/stun.service <<'EOF'
[Unit]
Description=UDP STUN server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/opt/nat/stun
Restart=on-failure
DynamicUser=yes

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/whoami.service <<'EOF'
[Unit]
Description=TCP who-am-I server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/opt/nat/whoami
Restart=on-failure
User=natuser

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now stun.service whoami.service
```

> **Docker fan?**  `docker run -d -p 3478:3478/udp -p 8080:8080 ghcr.io/earentir/nat-detection:latest` does the same.

---

## Running the client

```bash
natcheck --server your-vm.example.com:3478 \
         --echo   your-vm.example.com:8080 \
         --all-ifaces --proto auto
```

Typical output:

```bash
eth0 / IPv4  🔒 CG-NAT  (outside 203.0.113.42:60211, inside 10.4.0.15:60211, ASN 12345)
eth0 / IPv6  ✅ Global  (outside 2a02:587:abcd::1:60213)
wlan0 / IPv4 ✗ UDP blocked; TCP outside 198.51.100.17:61001 → symmetric CPE NAT
```

### Common flags

| flag | default | description |
|------|---------|-------------|
| `--iface`    | *(unset)* | test only this NIC (e.g. `eth0`) |
| `--all-ifaces` | `false` | iterate over every `UP` non‑loopback interface |
| `--proto`    | `auto`  | `auto` = UDP → TCP fallback, or force `udp`/`tcp` |
| `--timeout`  | `3s`    | dial + read timeout |
| `--asn-provider` | `cymru` | `cymru`, `ipinfo`, `disabled` |

---

## How detection works (quick refresher)

1. **UDP STUN Binding** – sees your public IP:port. If different from
   your socket’s inside address → you’re behind *some* NAT.
2. **TCP who‑am‑I** – same check to detect UDP blocking.
3. **ASN lookup** – disambiguate CG‑NAT vs regular home NAT when the
   inside address is in 10/8 or other private space not 100.64/10.
4. Interface enumeration gives per‑NIC, per‑family verdicts.

➡ see **[design.md](docs/design.md)** for full state diagram.

---

## Testing & linting

```bash
# run unit tests (currently only internal/stun)
go test ./...

# static checks (go vet + govulncheck)
make vet
```

CI runs the same checks in **GitHub Actions** (`.github/workflows/ci.yml`).

---

## Contributing

PRs and issues are welcome! Please run `build.sh` and `go test ./...`
locally before opening a pull‑request. Even typo fixes are appreciated.

---

## License

This project is distributed under the terms of the **MIT License** – see
[`LICENSE`](LICENSE) for full text.
