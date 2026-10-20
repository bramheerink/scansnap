# scansnap

A command-line tool that talks to Fujitsu **ScanSnap iX500** scanners over
WiFi on Linux. Put paper in, run one command, get a PDF. No GUI, no cloud,
no ScanSnap Home required.

The scanner speaks a proprietary protocol ("VENS") over UDP and TCP. See
[PROTOCOL](PROTOCOL) for the full reverse-engineered specification.

> May also work with other WiFi ScanSnap models (iX1500, etc.) — reports welcome.

## Requirements

- Python 3.8+ (standard library only — **no pip install needed**)
- `iproute2` (`ip` command, present on every Linux)

## Quick start

```sh
# 1. Find your scanner on the network
python3 scansnap.py discover

# 2. Put paper in the tray and scan
python3 scansnap.py scan -p PASS
```

## Commands

| Command | What it does |
|---|---|
| `discover` | Find all ScanSnap scanners on your /24 (model, serial, MAC) |
| `info [-s IP]` | Dump device info for one scanner |
| `status -p PASS [-s IP]` | Ports open? session free or locked? |
| `paper -p PASS [-s IP]` | Is there paper in the tray? |
| `scan -p PASS [-s IP] [-o out.pdf] [--jpeg] [--force]` | Scan all sheets → PDF (or JPEGs) |
| `release -p PASS [-s IP]` | Force-clear a stuck session lock |
| `listen` | Watch for scanner discovery broadcasts |

`-p/--password PASS` is the scanner's password. The default password is four
digits printed on the back of the scanner. It can be changed in ScanSnap Home.
Can be set via the `SCANSNAP_PASSWORD` environment variable.

`-s/--scanner IP` is optional everywhere — omit it and the scanner is
auto-discovered. Scanning does an automatic paper check first and refuses
politely if the tray is empty (override with `--force`).

## Troubleshooting

- **`session busy` / locked (`-4`/`-7`)** — another client (often ScanSnap
  Home's background agent on a Mac) is holding the scanner. Run
  `python3 scansnap.py release -p PASS -s IP`, or turn WiFi off on the other
  machine.
- **Scanner not found** — some access points block the discovery broadcast.
  `discover` falls back to a TCP subnet scan, but if that fails too, pass the
  IP explicitly with `-s`.
- **Wrong IP after a network change** — the scanner gets a new DHCP address;
  just run `discover` again (don't hardcode the IP).

## Legacy C driver

The original implementation was a single-binary C driver. It still lives in
[`legacy/`](legacy/) (with its own Dockerfile and build) but is no longer the
primary version — the Python tool above supersedes it and adds discovery,
diagnostics, paper detection and automatic session recovery. See
[legacy/README-c](legacy/README-c).

## License

GPL-2.0 — see [LICENSE](LICENSE).
