# Getting Started

mqvpn is an L3 multipath VPN built on MASQUE CONNECT-IP (RFC 9484) and Multipath QUIC.

## Installation

### Server

#### Debian and Ubuntu (deb packages)

The `mqvpn` deb contains the VPN program for both client and server; `mqvpn-server` adds the server service, NAT setup, and first-run configuration. Download the `mqvpn` and `mqvpn-server` debs of the same version from [Releases](https://github.com/mp0rta/mqvpn/releases/latest), then install both.

```bash
# Latest release version and the architecture of this machine
V=$(curl -fsSL https://api.github.com/repos/mp0rta/mqvpn/releases/latest \
  | grep -Po '"tag_name": "v\K[^"]+')
A=$(dpkg --print-architecture)
B=https://github.com/mp0rta/mqvpn/releases/download/v$V
curl -fLO $B/mqvpn_${V}_$A.deb -fLO $B/mqvpn-server_${V}_$A.deb
sudo apt install ./mqvpn_${V}_$A.deb ./mqvpn-server_${V}_$A.deb
```

The install generates a certificate, auth key, and server config, then starts the server and registers it for automatic startup on boot. It keeps a certificate or config that already exists. The generated config turns on hybrid mode and the reorder buffer on the server side; each takes effect only for clients that also turn it on. It also sets `AllowClientScheduler = true`, so a client can ask for its own download scheduler.

The install prints the auth key and a connection link with a QR code (see [Quick Start](#quick-start)). Run `sudo mqvpn-server-info` to show them again.

The install asks for a client subnet only when the default `10.0.0.0/24` overlaps a network of the server, and for the port only when UDP 443 is already in use. To set values in advance, for example in automation:

```bash
echo 'mqvpn-server mqvpn-server/subnet string 10.8.0.0/24' | sudo debconf-set-selections
sudo env MQVPN_PORT=10020 apt install ./mqvpn_${V}_$A.deb ./mqvpn-server_${V}_$A.deb
```

These values apply only to a new `/etc/mqvpn/server.conf`. To change a running server, edit `/etc/mqvpn/server.conf` and run `sudo systemctl restart mqvpn-server`.

`sudo apt remove mqvpn-server` stops the server and keeps `/etc/mqvpn`. `sudo apt purge mqvpn-server` also deletes the generated config, auth key, and certificate, so every client then needs the new auth key. Files that you created yourself stay. More details: `/usr/share/doc/mqvpn-server/README.Debian`.

::: tip Upgrading from 0.19.2 or earlier
The server files moved from the `mqvpn` deb to the new `mqvpn-server` deb. Install both debs together. Your `/etc/mqvpn` config stays as it is. If you used the install script before, first run it with `--uninstall` (it keeps `/etc/mqvpn`).
:::

#### Other Linux distributions (install script)

Run the following to install the binary to `/usr/local` and generate the same certificate, auth key, and server config as the deb.

```bash
curl -fsSL https://github.com/mp0rta/mqvpn/releases/latest/download/install.sh | sudo bash
```

Add `--start` to also start the server and register it for automatic startup on boot.

```bash
curl -fsSL https://github.com/mp0rta/mqvpn/releases/latest/download/install.sh \
    | sudo bash -s -- --start
```

Port and subnet can be customized with additional options.

```bash
curl -fsSL https://github.com/mp0rta/mqvpn/releases/latest/download/install.sh \
    | sudo bash -s -- --start --port 10020 --subnet 10.8.0.0/24
```

The script also installs `mqvpn-server-info` and runs it at the end, so `sudo mqvpn-server-info` works the same way as on the deb. To uninstall, re-run the script with `--uninstall` (add `--purge` to also remove config files).

::: warning
Both install methods generate a self-signed certificate when the server has none. Connecting with the link is safe with that certificate, because the link carries the fingerprint of the server's public key (the "pin"), which lets the client recognise the real server. If you want to run the server under a domain name, replace the certificate with one from a certificate authority such as Let's Encrypt. Both are fully supported ways to run a server. `--insecure` skips the server check completely and is for testing only. If an existing client config still has `Insecure = true`, remove that line when you use a pin or a link. The deb keeps a certificate that is already in place.
Point `--cert` (or `Cert` / `cert_file` in a config file) at the full chain file (for Let's Encrypt, `fullchain.pem`): clients do not fetch missing intermediates.
:::

### Client (Debian and Ubuntu)

Download the latest `mqvpn` deb from [Releases](https://github.com/mp0rta/mqvpn/releases/latest).

```bash
# Latest release version and the architecture of this machine
V=$(curl -fsSL https://api.github.com/repos/mp0rta/mqvpn/releases/latest \
  | grep -Po '"tag_name": "v\K[^"]+')
A=$(dpkg --print-architecture)
curl -fLO https://github.com/mp0rta/mqvpn/releases/download/v$V/mqvpn_${V}_$A.deb
sudo apt install ./mqvpn_${V}_$A.deb
```

### Windows client

Pre-built binaries are shipped for Windows amd64 and arm64. Download `mqvpn_<VERSION>_windows_<ARCH>.zip` from [Releases](https://github.com/mp0rta/mqvpn/releases/latest), extract, and follow the bundled `README.txt` (admin PowerShell required).

### macOS client

Pre-built binaries are shipped for Apple silicon (arm64). Download `mqvpn_<VERSION>_darwin_arm64.tar.gz` from [Releases](https://github.com/mp0rta/mqvpn/releases/latest), extract, and follow the bundled `README.txt` (sudo required).

### Build from source

See [Building](./building) for instructions.

## Quick Start

On the server, show the connection link:

```bash
sudo mqvpn-server-info
```

It prints the link (`mqvpn://…`) and a QR code of it (the QR code is drawn only when the command runs in a terminal; when its output is piped or saved to a file, the QR code is left out) and, in a terminal, the command to run on the client. The link holds the server address, the auth key and the pin. On the client, connect with the link:

```bash
sudo mqvpn --connect 'mqvpn://203.0.113.5:443?key=YOUR_KEY&pin=YOUR_PIN'
```

Keep the link in single quotes; it contains `?` and `&`. In the Windows Command Prompt, use double quotes instead.

Multipath (multiple interfaces):

```bash
sudo mqvpn --connect 'mqvpn://203.0.113.5:443?key=YOUR_KEY&pin=YOUR_PIN' \
    --path eth0 --path wlan0
```

With DNS override (prevents DNS leaks):

```bash
sudo mqvpn --connect 'mqvpn://203.0.113.5:443?key=YOUR_KEY&pin=YOUR_PIN' \
    --dns 1.1.1.1 --dns 8.8.8.8
```

`--connect` can be combined with other client options such as `--kill-switch`, and with `--config FILE` (the link then replaces the server address, key and pin of the file). It cannot be combined with `--server`, `--auth-key`, `--pin`, `--insecure` or `--mode server`. When `--connect` is used with `--config`, the file's `Insecure` and `ServerName` settings are not used. It works in the client on Linux, Windows and macOS.

::: warning
The link and the QR code contain the auth key. Treat them like a password: do not post screenshots, and remember that anyone with the link can connect. A link typed on a command line is also kept in your shell history, and while the client runs, the link (and so the auth key) is visible to other users of that computer in the process list, the same as with `--auth-key`. Take the link only from the server's owner, over a channel you trust: a link that someone changed on the way can point the client at their server.
:::

### About the link

- With the certificate that the install generated, the link includes a `pin`. The client then trusts only a server that holds that key; it does not check the certificate's name, expiry or issuer, so the certificate's expiry date does not matter. The link also keeps working if the certificate is re-issued with the same key. If the server's key is replaced, clients need the new link.
- With a certificate from a certificate authority (such as Let's Encrypt), the link has no `pin`. The host is the certificate's first DNS name (or the one you give with `--host`), and the client checks the certificate as usual.
- The address in the link is the server's own address. If that address is a private one (as on AWS, GCP and similar clouds, or behind a home router), `mqvpn-server-info` asks an external service (`ifconfig.me`) once for the server's public address. If the server's address is public on its own interface (most VPS providers), nothing is asked. To set the address yourself, and to ask nothing, use `sudo mqvpn-server-info --host ADDR[:PORT]`. If the lookup fails, it prints a hint to do this.
- The link carries the server's shared auth key (`[Auth] Key`). If each user has their own key (`User = NAME:KEY`), make one link per user with `sudo mqvpn-server-info --user NAME`; the pin is the same for every user. This works for users in the config file, not for users added only through the control API.
- The QR code is a convenient way to carry the link: any QR reader shows the `mqvpn://…` text. The Android and iOS apps do not read it yet.

### Without a link

The link is a shortcut. You can still give the server address and the auth key yourself:

```bash
sudo mqvpn --mode client --server YOUR_SERVER:443 \
    --auth-key YOUR_AUTH_KEY --pin YOUR_PIN
```

`--pin` (or `Pin` in the `[Server]` section of a config file) is the pin from the link. Leave it out if the server has a certificate from a certificate authority. `--insecure` (or `Insecure = true`) means "do not check the server at all"; it is for testing only; it cannot be combined with a pin, and mqvpn refuses to start if both are set.

::: tip
Without `--path`, the client uses the default interface (single path). Multipath requires two or more `--path` flags. See [Multipath](./multipath) for details.
:::

::: warning
The server needs its listen port open for UDP (default: 443). All client traffic is routed through the tunnel.
:::

## Generate an Auth Key

```bash
mqvpn --genkey
```

The install script and `start_server.sh` generate one automatically.

## CLI Reference

```
mqvpn --config PATH
mqvpn --mode client|server [options]

  --server HOST:PORT     Server address (client, e.g. `[2001:db8::1]:443` for IPv6)
  --connect LINK         Connect with an mqvpn:// link (client)
  --pin PIN              Server public-key pin, 43 characters (client)
  --show-link            Print a connection link and QR code, then exit (server)
  --host ADDR[:PORT]     Address clients use to reach this server (with --show-link)
  --link-user NAME       Put this user's key in the link (with --show-link)
  --path IFACE           Multipath interface (repeatable)
  --auth-key KEY         PSK authentication
  --user NAME:KEY[:IP]   Per-user PSK; IP fixes the user's VPN address (repeatable, server)
  --dns ADDR             DNS server (repeatable)
  --tls-server-name NAME TLS SNI / cert verify name (client)
  --insecure             Accept untrusted certs (testing only)
  --tun-name NAME        TUN device name (default: mqvpn0)
  --listen BIND:PORT     Listen address (server, default: 0.0.0.0:443)
  --subnet CIDR          Client IPv4 pool (server)
  --subnet6 CIDR         Client IPv6 pool (server)
  --cert PATH            TLS certificate (server)
  --key PATH             TLS private key (server)
  --scheduler SCHED      Multipath scheduler: minrtt|wlb|wlb_udp_pin|backup_fec
                         (default: wlb)
  --cc ALGO              Congestion control: bbr2|bbr|cubic|none (default: bbr2)
  --mtu N                TUN MTU (1280-9000, default: auto)
  --path-mtu N           Underlay MTU to size QUIC packets for (1280-9000, default: 0)
  --pmtud                Discover the path MTU (both ends); --path-mtu is the upper limit
  --max-clients N        Max concurrent clients (server, default: 64)
  --control-port PORT    TCP port for control API (server)
  --control-addr ADDR    Bind address for control API (default: 127.0.0.1)
  --status               Query server status via control API and exit
  --log-level LVL        Log level (debug|info|warn|error)
  --no-reconnect         Disable automatic reconnection (client)
  --kill-switch          Block traffic outside the VPN tunnel (client)
  --no-manage-routes     Do not modify the host routing table (client)
  --genkey               Generate PSK and exit
  --version              Show version and exit
  --help                 Show all options
```

When `--config` is provided, `--mode` is inferred from the config file. CLI arguments override config values.

## Next Steps

- [Building](./building) — Build from source on Linux, Windows, and Android
- [Configuration](./configuration) — Config file reference
- [Multipath](./multipath) — Multipath setup and scheduler options
