# Button Daemon Roadmap

This is a follow-up feature for after the v0.1 active-scan release.

## Current Finding

The available ScanSnap Home captures show the official client actively
owning or preparing a scanner session before image data is transferred.
They do not show a standalone scanner-initiated callback that a passive
client can simply wait for after the physical button is pressed.

## Working Hypothesis

A daemon mode should behave like a long-running scanner owner:

- Register with the scanner and complete the normal 53219 handshake.
- Initialize or prepare the 53218 scan session.
- Poll status or keep the scanner in a ready state.
- Start/receive image transfer when the scanner reports a button-triggered
  scan.
- Write timestamped PDFs into the configured output directory.
- Release the scanner session on `SIGINT` and `SIGTERM`.

## Proposed CLI

```sh
scansnap --daemon -s SCANNER_IP -o /work
```

The daemon should use the same pairing-key lookup as normal scans. The
`-o` argument should be interpreted as an output directory in daemon mode.

## Capture Needed Before Implementation

Capture one clean run where:

- ScanSnap Home is already open and idle before capture starts.
- Wireshark is recording before the physical scanner button is pressed.
- The physical scanner button starts the scan.
- Capture continues until the resulting PDF/file is written.

The key question is whether the button press is visible as a status change
on an existing 53218 session or whether ScanSnap Home uses another trigger
path before issuing the normal scan commands.

## Out Of Scope For v0.1

- Background daemon implementation.
- Auto-reconnect/backoff behavior.
- Multi-scanner support.
- Service unit or container restart policy.
