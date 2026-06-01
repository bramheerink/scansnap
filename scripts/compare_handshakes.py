#!/usr/bin/env python3
import argparse
import shutil
import subprocess
import sys


REQUEST_PREFIX = "0000008056454e5300000011"


def tshark_path() -> str:
    return shutil.which("tshark") or "/Applications/Wireshark.app/Contents/MacOS/tshark"


def run_tshark(pcap: str):
    cmd = [
        tshark_path(),
        "-r",
        pcap,
        "-Y",
        "tcp.port==53219 && tcp.len>0",
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "tcp.stream",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "tcp.srcport",
        "-e",
        "tcp.dstport",
        "-e",
        "data",
    ]
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return [line.split("\t") for line in result.stdout.splitlines() if line.strip()]


def extract_first_request(pcap: str):
    for fields in run_tshark(pcap):
        if len(fields) < 7:
            continue
        frame_no, stream, src, dst, sport, dport, data = fields[:7]
        if data.startswith(REQUEST_PREFIX):
            return {
                "frame": int(frame_no),
                "stream": stream,
                "src": src,
                "dst": dst,
                "sport": sport,
                "dport": dport,
                "hex": data,
            }
    return None


def print_diff(left: bytes, right: bytes):
    for i, (a, b) in enumerate(zip(left, right)):
        if a != b:
            print(f"{i:03d}: {a:02x} != {b:02x}")
    if len(left) != len(right):
        print(f"length differs: {len(left)} != {len(right)}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare first TCP 0x11 ScanSnap handshake request in two pcaps.")
    parser.add_argument("left")
    parser.add_argument("right")
    args = parser.parse_args()

    left = extract_first_request(args.left)
    right = extract_first_request(args.right)

    if not left:
        print(f"No TCP 0x11 handshake request found in {args.left}", file=sys.stderr)
        return 1
    if not right:
        print(f"No TCP 0x11 handshake request found in {args.right}", file=sys.stderr)
        return 1

    print(f"left : frame {left['frame']} stream {left['stream']} {left['src']}:{left['sport']} -> {left['dst']}:{left['dport']}")
    print(f"right: frame {right['frame']} stream {right['stream']} {right['src']}:{right['sport']} -> {right['dst']}:{right['dport']}")
    print_diff(bytes.fromhex(left["hex"]), bytes.fromhex(right["hex"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
