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

# 2. One-time: capture the pairing key from ScanSnap Home (see below)
python3 scansnap.py pair --name iX500-<YOUR-SERIAL>

# 3. Put paper in the tray and scan
python3 scansnap.py scan
```

The pairing key is saved to `~/.config/scansnap/key` and reused automatically.

## Commands

| Command | What it does |
|---|---|
| `discover` | Find all ScanSnap scanners on your /24 (model, serial, MAC) |
| `info -s IP` | Dump device info for one scanner |
| `status -s IP` | Ports open? session free or locked? |
| `paper -s IP` | Is there paper in the tray? |
| `scan [-s IP] [-o out.pdf] [--jpeg] [--force]` | Scan all sheets → PDF (or JPEGs) |
| `pair [--name NAME]` | Capture the pairing key (fake-scanner trick) |
| `release -s IP` | Force-clear a stuck session lock |
| `listen` | Watch for scanner discovery broadcasts |

`-s/--scanner IP` is optional everywhere — omit it and the scanner is
auto-discovered. Scanning does an automatic paper check first and refuses
politely if the tray is empty (override with `--force`).

## Pairing (one time)

Your scanner is bound to a key — the serial number of its internal WiFi
module. ScanSnap Home knows this key, so we trick it into telling us:

1. Turn the **real scanner off** (or disconnect it).
2. Run `python3 scansnap.py pair --name iX500-<YOUR-SERIAL>` (the serial is
   printed on the label on the bottom of the scanner). Ports 52217/53218/53219
   must be free — you may need `sudo` if something else is bound to them.
3. Open **ScanSnap Home** on your Mac or Windows machine. It finds the fake
   scanner and sends the pairing key, which is saved to `~/.config/scansnap/key`.

You only do this once.

## Troubleshooting

- **`session busy` / locked (`-4`/`-7`)** — another client (often ScanSnap
  Home's background agent on a Mac) is holding the scanner. Run
  `python3 scansnap.py release -s IP`, or turn WiFi off on the other machine.
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
