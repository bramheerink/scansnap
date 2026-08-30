#!/usr/bin/env python3
"""scansnap — unified WiFi driver + diagnostics for the Fujitsu ScanSnap iX500.

Speaks the reverse-engineered VENS protocol. One tool for everything:

  scansnap discover                 find scanners on the local /24
  scansnap info    <IP>             device info (model, serial, MAC)
  scansnap status  <IP>             session state + paper check
  scansnap paper   <IP>             is there paper in the tray?
  scansnap scan    [-s IP] [-o f]   scan all sheets -> PDF (or --jpeg)
  scansnap pair                     capture the pairing key (fake-scanner trick)
  scansnap release <IP>             force-clear a stuck session lock
  scansnap listen                   watch for scanner 53220 broadcasts

Ports: 52217/udp register  53220/udp discovery  53218/tcp scan  53219/tcp handshake
Pairing key is read from / written to ~/.config/scansnap/key.
"""
import argparse, os, re, socket, struct, subprocess, sys, threading, time, ipaddress

REG_PORT, DISC_PORT, SCAN_PORT, HS_PORT = 52217, 53220, 53218, 53219
CLIENT_UDP_PORT = 55264
SILEX_MAC = bytes.fromhex("00809258c15c")
KEY_PATH = os.path.expanduser("~/.config/scansnap/key")
VENS_HELLO = bytes.fromhex("0000001056454e530000000000000000")

# ── pairing key storage ─────────────────────────────────────────────────────

def load_key():
    try:
        with open(KEY_PATH) as f:
            return f.read().strip().encode()
    except OSError:
        return None

def save_key(key: bytes):
    os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
    with open(KEY_PATH, "w") as f:
        f.write(key.decode())
    os.chmod(KEY_PATH, 0o600)

# ── low-level ────────────────────────────────────────────────────────────────

def local_ip_toward(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((ip, 1)); return s.getsockname()[0]
    finally:
        s.close()

def wifi_mac_toward(ip):
    out = subprocess.check_output(["ip", "route", "get", ip]).decode()
    iface = re.search(r'dev (\S+)', out).group(1)
    out2 = subprocess.check_output(["ip", "link", "show", iface]).decode()
    mac = re.search(r'link/ether ([0-9a-f:]+)', out2).group(1)
    return bytes.fromhex(mac.replace(":", "")), mac

def tcp_open(ip, port, timeout=0.5):
    s = socket.socket(); s.settimeout(timeout)
    try:
        s.connect((ip, port)); return True
    except OSError:
        return False
    finally:
        s.close()

def vens_pkt(mac, cmd_hex):
    cmd = bytes.fromhex(cmd_hex) if isinstance(cmd_hex, str) else cmd_hex
    return struct.pack(">I", 32 + len(cmd)) + b"VENS" + struct.pack(">II", 1, 0) \
        + mac + b"\x00" * 10 + cmd

def recv_vens(sock, timeout=5):
    sock.settimeout(timeout)
    try:
        hdr = sock.recv(16)
    except socket.timeout:
        return None
    if len(hdr) < 16:
        return None
    ln = struct.unpack(">I", hdr[:4])[0]
    payload = b""
    while len(payload) < ln - 16:
        chunk = sock.recv(ln - 16 - len(payload))
        if not chunk:
            break
        payload += chunk
    return hdr + payload

# ── device info (132B registration reply) ────────────────────────────────────

def decode_devinfo(b):
    if len(b) < 34 or b[0:4] != b"VENS":
        return None
    info = {"ip": socket.inet_ntoa(b[16:20]),
            "port1": struct.unpack(">I", b[20:24])[0],
            "port2": struct.unpack(">I", b[24:28])[0],
            "mac": b[28:34].hex(":")}
    strings = [m.group().decode() for m in re.finditer(rb'[\x20-\x7e]{4,}', b)]
    model = next((s for s in strings if s != "VENS"), None)
    friendly = next((s for s in strings if s.startswith("ScanSnap")), None)
    if model:
        info["model"] = model
        if "-" in model:
            info["serial"] = model.split("-", 1)[1]
    if friendly:
        info["friendly"] = friendly.strip()
    return info

def register_probe(ip, mac, my_ip, timeout=2.0):
    """Send the 3-magic registration to ip:52217. Returns devinfo or None.
    NB: this registers us with the scanner (mild session side effect)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", CLIENT_UDP_PORT))
    except OSError:
        s.bind(("0.0.0.0", 0))
    s.settimeout(timeout)
    ipb = socket.inet_aton(my_ip)
    for magic, flags, ver in [(b"VENS", 0x0010, 0), (b"ssNR", 0x0100, 0), (b"V2ss", 0x1000, 1)]:
        pkt = bytearray(32)
        pkt[0:4] = magic
        if ver:
            pkt[4:8] = struct.pack(">I", 1)
        pkt[8:12] = ipb
        pkt[12:18] = mac
        pkt[22:24] = struct.pack(">H", 0xd7e0)
        pkt[24:26] = struct.pack(">H", flags)
        s.sendto(bytes(pkt), (ip, REG_PORT))
    try:
        data, _ = s.recvfrom(512)
        return decode_devinfo(data)
    except socket.timeout:
        return None
    finally:
        s.close()

def register_rounds(ip, mac, my_ip, rounds=4):
    """Full registration burst (4 rounds x 3 magics) like the Mac does."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", CLIENT_UDP_PORT))
    except OSError:
        s.bind(("0.0.0.0", 0))
    s.settimeout(3)
    ipb = socket.inet_aton(my_ip)
    for _ in range(rounds):
        for magic, flags, ver in [(b"VENS", 0x0010, 0), (b"ssNR", 0x0100, 0), (b"V2ss", 0x1000, 1)]:
            pkt = bytearray(32)
            pkt[0:4] = magic
            if ver:
                pkt[4:8] = struct.pack(">I", 1)
            pkt[8:12] = ipb
            pkt[12:18] = mac
            pkt[22:24] = struct.pack(">H", 0xd7e0)
            pkt[24:26] = struct.pack(">H", flags)
            s.sendto(bytes(pkt), (ip, REG_PORT))
    try:
        s.recvfrom(512)
    except socket.timeout:
        pass
    s.close()

# ── handshake / session ───────────────────────────────────────────────────────

def handshake_code(ip, mac, my_ip, key, timeout=4.0):
    """128B conn1 handshake. Returns (err, raw_hex). 0=ok, -4=busy, -7=other IP."""
    s = socket.socket(); s.settimeout(timeout)
    try:
        s.connect((ip, HS_PORT))
    except OSError as e:
        return None, f"connect fail: {e}"
    try:
        s.recv(16)
        pkt = bytearray(bytes.fromhex(
            "0000008056454e530000001100000000"
            "026c251c14ce00000000000000000000"
            "00061e000000000000000001c0a80199"
            "0000d7e1000000000000000000000000"
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
            "0000000007ea030a15001a0036c7c7e4"
            "7a800000ffff9d900000000000000000"))
        pkt[16:22] = mac
        pkt[44:48] = socket.inet_aton(my_ip)
        if key:
            pkt[52:68] = b"\x00" * 16
            pkt[52:52 + len(key[:16])] = key[:16]
        s.send(bytes(pkt))
        resp = s.recv(256)
        err = struct.unpack(">i", resp[8:12])[0] if len(resp) >= 12 else None
        return err, resp.hex()
    finally:
        try: s.shutdown(socket.SHUT_RDWR)
        except OSError: pass
        s.close()

def handshake_aux(ip, mac, n):
    """conn2 (cmd 0x13) / conn3 (cmd 0x30) of the 3-way handshake."""
    cmd = 0x13 if n == 2 else 0x30
    try:
        s = socket.socket(); s.settimeout(5)
        s.connect((ip, HS_PORT)); s.recv(16)
        pkt = bytearray(32)
        pkt[0:4] = struct.pack(">I", 32); pkt[4:8] = b"VENS"
        pkt[8:12] = struct.pack(">I", cmd); pkt[16:22] = mac
        s.send(bytes(pkt)); s.recv(256)
        s.shutdown(socket.SHUT_RDWR); s.close()
    except OSError:
        pass

def d6_release(ip, mac):
    try:
        s = socket.socket(); s.settimeout(4)
        s.connect((ip, SCAN_PORT)); s.recv(16)
        s.send(vens_pkt(mac, "00000006000000000000000000000000d6000000000000000000000000000000"))
        recv_vens(s, 2)
        s.shutdown(socket.SHUT_RDWR); s.close()
        return True
    except OSError:
        return False

def grab_session(ip, mac, my_ip, key, tries=8, verbose=False):
    """Register + handshake until err==0, hammering D6-release on -4/-7."""
    for i in range(tries):
        register_rounds(ip, mac, my_ip)
        err, _ = handshake_code(ip, mac, my_ip, key)
        if verbose:
            print(f"  handshake poging {i}: err={err}")
        if err == 0:
            return True
        d6_release(ip, mac)
        time.sleep(0.3)
    return False

QUERY_CMDS = {
    "06+12": "0000000600000060000000000000000012000000600000000000000000000000",
    "E7":    "0000000a0000000c0000000000000000e70001000000000c0000000000000000",
    "C2":    "0000000a000000200000000000000000c2000000000000002000000000000000",
    "E6a":   "00000008000000040000000000000000e6000100000000040000000000000000",
    "E6b":   "00000008000000000000000400000000e6000000000400000000000000000000101e0000",
}

# C2 byte 43 is an EMPTY flag: 0x80 = tray empty, 0x00 = paper present (iX500).
PAPER_EMPTY_OFFSET, PAPER_EMPTY_MASK = 43, 0x80

def read_status(ip, mac, my_ip, key):
    """Open a session, return {label: raw} for status queries, D6-clean up."""
    if not grab_session(ip, mac, my_ip, key):
        return None
    c = socket.socket(); c.settimeout(6)
    c.connect((ip, SCAN_PORT)); c.recv(16)
    out = {}
    try:
        for lbl in ("06+12", "E7", "C2", "E6a", "E6b"):
            c.send(vens_pkt(mac, QUERY_CMDS[lbl]))
            out[lbl] = recv_vens(c) or b""
        c.send(vens_pkt(mac, "00000006000000000000000000000000d6000000000000000000000000000000"))
        recv_vens(c)
    finally:
        try: c.shutdown(socket.SHUT_RDWR)
        except OSError: pass
        c.close()
    return out

def paper_present(c2):
    if len(c2) <= PAPER_EMPTY_OFFSET:
        return None
    return not (c2[PAPER_EMPTY_OFFSET] & PAPER_EMPTY_MASK)

# ── discovery ─────────────────────────────────────────────────────────────────

def tcp_sweep(my_ip, timeout=0.5, workers=64):
    net = ipaddress.ip_network(my_ip + "/24", strict=False)
    found, lock = [], threading.Lock()
    sem = threading.BoundedSemaphore(workers)

    def probe(ip):
        with sem:
            if tcp_open(ip, SCAN_PORT, timeout) and tcp_open(ip, HS_PORT, timeout):
                with lock: found.append(ip)
    ts = [threading.Thread(target=probe, args=(str(h),)) for h in net.hosts()]
    for t in ts: t.start()
    for t in ts: t.join()
    return sorted(found, key=lambda x: int(x.split(".")[-1]))

def passive_listen(seconds):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", DISC_PORT))
    except OSError:
        return []
    s.settimeout(seconds)
    seen, out = set(), []
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            data, addr = s.recvfrom(512)
        except socket.timeout:
            break
        if len(data) >= 34 and data[4:8] == b"VENS":
            ip = socket.inet_ntoa(data[24:28])
            if ip not in seen:
                seen.add(ip)
                out.append({"ip": ip, "mac": data[28:34].hex(":"), "src": "53220-broadcast"})
    s.close()
    return out

def find_scanners(listen=2.0, timeout=0.5):
    my_ip = local_ip_toward("8.8.8.8")
    mac, _ = wifi_mac_toward("8.8.8.8")
    results = {}
    for d in passive_listen(listen):
        results.setdefault(d["ip"], {}).update(d)
    for ip in tcp_sweep(my_ip, timeout=timeout):
        results.setdefault(ip, {}).update({"ip": ip, "ports": "53218+53219 open"})
    for ip in list(results):
        info = register_probe(ip, mac, my_ip, timeout=1.5)
        if info:
            results[ip].update(info)
    return results

# ── scan ──────────────────────────────────────────────────────────────────────

def _scan_start_cmd(pc):
    cmd = bytearray.fromhex("0000000c00300000000000000000000028000002000030000000000000000000")
    if pc % 2 == 1:
        cmd[21] = 0x80
    cmd[26] = pc
    return cmd

def _done_query_cmd(pc):
    cmd = bytearray.fromhex("0000000c00000020000000000000000028008000008000002000000000000000")
    cmd[26] = pc
    return cmd

SCAN_CMDS = [
    "0000000a000000200000000000000000c2000000000000002000000000000000",
    "00000006000000080000000800000000d50000000808000000000000000000000000000000000000",
    "00000006000000000000000000000000d8000000000000000000000000000000",
    "0000000a000000000000002000000000e9000000000000200000000000000000012c012c000028d0000044dc0500000000000000000000000000000000000000",
    "00000006000000000000005000000000d400000050000000000000000000000000030101d000c1808080908080000000000000000000000000000000000000300010012c012c05810000000028d0000044dc040000000000000000000000000000000000000000000000000000000000",
    "0000000a000000200000000000000000c2000000000000002000000000000000",
    "0000000600000012000000000000000003000000120000000000000000000000",
    "00000006000000000000000000000000e0000000000000000000000000000000",
]
INIT_CMDS = [
    "0000000600000060000000000000000012000000600000000000000000000000",
    "0000000a0000000c0000000000000000e70001000000000c0000000000000000",
    "0000000a000000200000000000000000c2000000000000002000000000000000",
    "00000008000000040000000000000000e6000100000000040000000000000000",
    "00000008000000000000000400000000e6000000000400000000000000000000101e0000",
    "00000006000000080000000800000000d50000000808000000000000000000000000000000000000",
    "00000006000000000000000000000000d6000000000000000000000000000000",
]

def scan(ip, key, verbose=False):
    """Run a full scan session. Returns list of JPEG byte strings (pages)."""
    my_ip = local_ip_toward(ip)
    mac, mac_str = wifi_mac_toward(ip)
    if verbose:
        print(f"MAC={mac_str} IP={my_ip}")

    if not grab_session(ip, mac, my_ip, key, verbose=verbose):
        raise RuntimeError("kon de sessie niet grijpen (handshake != 0). Probeer 'release' of zet Mac-WiFi uit.")

    # init session on 53218 with parallel aux handshakes (conn2/conn3)
    s = socket.socket(); s.settimeout(10)
    s.connect((ip, SCAN_PORT)); s.recv(16)
    t2 = threading.Thread(target=handshake_aux, args=(ip, mac, 2)); t2.start()
    t3 = threading.Thread(target=handshake_aux, args=(ip, mac, 3))
    for i, cmd in enumerate(INIT_CMDS):
        s.send(vens_pkt(mac, cmd))
        if recv_vens(s) is None:
            raise RuntimeError("init-sessie afgebroken")
        if i == 0:
            t3.start()
    t2.join(timeout=5); t3.join(timeout=5)
    try: s.shutdown(socket.SHUT_RDWR)
    except OSError: pass
    s.close()

    register_rounds(ip, mac, my_ip, rounds=1)

    # scan connection
    s = socket.socket(); s.settimeout(15)
    s.connect((ip, SCAN_PORT)); s.recv(16)
    for cmd in SCAN_CMDS:
        s.send(vens_pkt(mac, cmd))
        if recv_vens(s) is None:
            raise RuntimeError("scan-setup afgebroken")

    pages, prepend, pc, scanning = [], b"", 0, True
    s.send(vens_pkt(mac, _scan_start_cmd(pc)))
    if verbose:
        print("  -> START SCAN")
    while scanning:
        s.settimeout(30)
        image, prepend = prepend, b""
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    scanning = False; break
                image += chunk
                if b'\xff\xd9' in image:
                    eoi = image.rfind(b'\xff\xd9')
                    prepend = image[eoi + 2:]
                    image = image[:eoi + 2]
                    break
        except socket.timeout:
            pass
        start = image.find(b'\xff\xd8')
        if start < 0:
            break
        pages.append(image[start:])
        if verbose:
            print(f"    page {pc + 1}: {len(image[start:])} bytes")

        if pc % 2 == 1:  # after a back page: between-sheet handshake
            s.send(vens_pkt(mac, "0000000600000012000000000000000003000000120000000000000000000000"))
            if recv_vens(s) is None:
                break
            s.send(vens_pkt(mac, _done_query_cmd(pc))); recv_vens(s)
            s.send(vens_pkt(mac, "0000000a000000200000000000000000c2000000000000002000000000000000")); recv_vens(s)
            s.send(vens_pkt(mac, "00000006000000000000000000000000e0000000000000000000000000000000")); recv_vens(s)
            s.send(vens_pkt(mac, "0000000600000012000000000000000003000000120000000000000000000000"))
            resp = recv_vens(s)
            if resp is None or resp[-12:] != b'\x00' * 12:
                break  # no more sheets
            pc += 1
            s.send(vens_pkt(mac, _scan_start_cmd(pc)))
            s.settimeout(15)
            try:
                ack = s.recv(256)
            except socket.timeout:
                break
            if not ack:
                break
            if b'\xff\xd8' in ack:
                prepend = ack
        else:            # after a front page: request the back page
            s.send(vens_pkt(mac, "0000000600000012000000000000000003000000120000000000000000000000"))
            if recv_vens(s) is None:
                break
            pc += 1
            s.send(vens_pkt(mac, _scan_start_cmd(pc)))
            s.settimeout(10)
            try:
                ack = s.recv(256)
            except socket.timeout:
                break
            if not ack:
                break
            if b'\xff\xd8' in ack:
                prepend = ack

    # cleanup: FIN, then a brief D6-release connection like the Mac does
    try:
        s.shutdown(socket.SHUT_WR); s.settimeout(2)
        try: s.recv(1024)
        except OSError: pass
        s.close()
    except OSError:
        pass
    time.sleep(1)
    d6_release(ip, mac)
    return pages

# ── minimal JPEG->PDF (no dependencies) ───────────────────────────────────────

def _write_pdf(jpegs, path, jpeg_dims):
    buf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    def obj(nid, body):
        offsets[nid] = len(buf)
        buf.extend(f"{nid} 0 obj\n".encode()); buf.extend(body); buf.extend(b"\nendobj\n")
    n = len(jpegs)
    obj(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    kids = " ".join(f"{3 + 3*i} 0 R" for i in range(n))
    obj(2, f"<< /Type /Pages /Count {n} /Kids [{kids}] >>".encode())
    for i, jp in enumerate(jpegs):
        w, h = jpeg_dims(jp)
        pw, ph = w * 72 / 300.0, h * 72 / 300.0
        pid, cid, iid = 3 + 3*i, 4 + 3*i, 5 + 3*i
        obj(pid, (f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {pw:.2f} {ph:.2f}] "
                  f"/Resources << /XObject << /Im0 {iid} 0 R >> >> /Contents {cid} 0 R >>").encode())
        content = f"q {pw:.2f} 0 0 {ph:.2f} 0 0 cm /Im0 Do Q".encode()
        obj(cid, b"<< /Length %d >>\nstream\n%s\nendstream" % (len(content), content))
        img_hdr = (f"<< /Type /XObject /Subtype /Image /Width {w} /Height {h} "
                   f"/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode "
                   f"/Length {len(jp)} >>").encode()
        offsets[iid] = len(buf)
        buf.extend(f"{iid} 0 obj\n".encode()); buf.extend(img_hdr)
        buf.extend(b"\nstream\n"); buf.extend(jp); buf.extend(b"\nendstream\nendobj\n")
    xref_pos = len(buf)
    maxid = 2 + 3*n
    buf.extend(f"xref\n0 {maxid + 1}\n".encode())
    buf.extend(b"0000000000 65535 f \n")
    for nid in range(1, maxid + 1):
        buf.extend(f"{offsets.get(nid, 0):010d} 00000 n \n".encode())
    buf.extend(f"trailer\n<< /Size {maxid + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode())
    with open(path, "wb") as f:
        f.write(buf)

# ── pairing (fake-scanner trick) ──────────────────────────────────────────────

# 132B device-info template. The model/serial field at [40:56] is filled in at
# runtime from --name so no real serial is baked into the source.
_REG_TEMPLATE = bytes.fromhex(
    "56454e530000000000060030ffffffff"   # VENS header
    "c0a8018c0000cfe20000cfe300809258"   # ip(placeholder) ports mac...
    "c15c0000008000010000000000000000"   # ...mac end; model[40:48] zeroed
    "00000000000000000000000000000000"   # model[48:56] zeroed
    "00000000000000000000000000000000"
    "00000000000000000000000000000000"
    "00000000000000005363616e536e6170"   # "ScanSnap" at [104]
    "20695835303020200000000036c7c7e4"   # " iX500  " + tail start
    "7a800000")

def build_reg_resp(ip_bytes, mac, name):
    b = bytearray(_REG_TEMPLATE)
    b[16:20] = ip_bytes
    b[28:34] = mac
    b[40:56] = b"\x00" * 16
    enc = name.encode()[:16]
    b[40:40 + len(enc)] = enc
    return bytes(b)

def cmd_pair(args):
    """Pretend to be a scanner so ScanSnap Home hands us the pairing key."""
    my_ip = local_ip_toward("8.8.8.8")
    ipb = socket.inet_aton(my_ip)
    reg = bytearray(build_reg_resp(ipb, SILEX_MAC, args.name))
    print("Nep-scanner actief. Zorg dat:")
    print("  1. de ECHTE scanner UIT staat")
    print("  2. ScanSnap Home op je Mac open is (die stuurt dan de key)")
    print("Wachten op de pairing-key... (Ctrl-C om te stoppen)\n")
    stop = threading.Event()
    captured = {}

    def broadcaster():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        disc = bytearray(48)
        struct.pack_into(">I", disc, 0, 48); disc[4:8] = b"VENS"
        struct.pack_into(">I", disc, 8, 0x21); struct.pack_into(">I", disc, 16, 1)
        disc[24:28] = ipb; disc[28:34] = SILEX_MAC
        while not stop.is_set():
            try: s.sendto(bytes(disc), ("255.255.255.255", DISC_PORT))
            except OSError: pass
            stop.wait(3)
        s.close()

    def udp_responder():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", REG_PORT)); s.settimeout(1)
        while not stop.is_set():
            try:
                _, addr = s.recvfrom(512)
                s.sendto(bytes(reg), addr)
            except socket.timeout:
                continue
            except OSError:
                break
        s.close()

    def hs_listener():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", HS_PORT)); s.listen(5); s.settimeout(1)
        while not stop.is_set():
            try:
                conn, addr = s.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.settimeout(5)
                conn.send(VENS_HELLO)
                data = conn.recv(512)
                if len(data) >= 68 and struct.unpack(">I", data[0:4])[0] == 128:
                    key = data[52:68].rstrip(b"\x00")
                    if key and not captured:
                        captured["key"] = key
                        resp = bytearray(20)
                        struct.pack_into(">I", resp, 0, 20); resp[4:8] = b"VENS"
                        struct.pack_into(">I", resp, 12, 0x00060000)
                        conn.send(bytes(resp))
                        stop.set()
                conn.close()
            except OSError:
                pass
        s.close()

    def scan_listener():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("", SCAN_PORT)); s.listen(5); s.settimeout(1)
        except OSError:
            return
        while not stop.is_set():
            try:
                conn, _ = s.accept(); conn.send(VENS_HELLO); conn.close()
            except socket.timeout:
                continue
            except OSError:
                break
        s.close()

    threads = [threading.Thread(target=f, daemon=True)
               for f in (broadcaster, udp_responder, hs_listener, scan_listener)]
    for t in threads:
        t.start()
    try:
        while not stop.is_set():
            time.sleep(0.3)
    except KeyboardInterrupt:
        stop.set()
        print("\nGestopt zonder key.")
        return 1
    key = captured.get("key")
    if key:
        save_key(key)
        print(f"✓ Pairing-key opgevangen en opgeslagen: {key.decode()}  ({KEY_PATH})")
        return 0
    return 1

# ── CLI commands ──────────────────────────────────────────────────────────────

def _resolve_ip(args):
    ip = getattr(args, "ip", None) or getattr(args, "scanner", None)
    if ip:
        return ip
    print("Scanner zoeken...", file=sys.stderr)
    found = find_scanners()
    if not found:
        print("Geen scanner gevonden. Geef IP met -s.", file=sys.stderr)
        return None
    ip = sorted(found)[0]
    print(f"Scanner gevonden op {ip}", file=sys.stderr)
    return ip

def cmd_discover(args):
    results = find_scanners(listen=args.listen, timeout=args.timeout)
    if not results:
        print("Geen scanners gevonden."); return 1
    print(f"{len(results)} scanner(s) gevonden:\n")
    for ip, d in sorted(results.items(), key=lambda kv: int(kv[0].split('.')[-1])):
        print(f"  ● {ip}")
        print(f"      model : {d.get('friendly') or d.get('model') or 'onbekend (VENS-poorten open)'}")
        if d.get("serial"): print(f"      serial: {d['serial']}")
        if d.get("mac"):    print(f"      mac   : {d['mac']}")
        if d.get("port1"):  print(f"      ports : {d['port1']}/{d['port2']}")
    return 0

def cmd_info(args):
    ip = _resolve_ip(args)
    if not ip: return 1
    my_ip = local_ip_toward(ip); mac, _ = wifi_mac_toward(ip)
    info = register_probe(ip, mac, my_ip, timeout=3.0)
    if not info:
        print(f"Geen device-info van {ip}."); return 1
    print(f"Device-info {ip}:")
    for k in ("friendly", "model", "serial", "mac", "ip", "port1", "port2"):
        if k in info: print(f"  {k:9s}: {info[k]}")
    return 0

def cmd_status(args):
    ip = _resolve_ip(args)
    if not ip: return 1
    my_ip = local_ip_toward(ip); mac, mac_str = wifi_mac_toward(ip)
    key = load_key()
    print(f"Status {ip} (client MAC {mac_str}, IP {my_ip}):")
    p18, p19 = tcp_open(ip, SCAN_PORT), tcp_open(ip, HS_PORT)
    print(f"  53218 scan     : {'open' if p18 else 'dicht'}")
    print(f"  53219 handshake: {'open' if p19 else 'dicht'}")
    if not (p18 and p19):
        print("  -> poorten dicht: scanner uit, verkeerd IP, of AP-isolatie."); return 1
    err, _ = handshake_code(ip, mac, my_ip, key)
    if err == 0:
        d6_release(ip, mac)
    meaning = {0: "VRIJ", -4: "BUSY/LOCKED — gebruik 'release'",
               -7: "gepaird aan ander IP", -3: "onbekende pairing key"}.get(err, "onbekend")
    print(f"  sessie-status  : err={err} ({meaning})")
    return 0

def cmd_paper(args):
    ip = _resolve_ip(args)
    if not ip: return 1
    my_ip = local_ip_toward(ip); mac, _ = wifi_mac_toward(ip)
    st = read_status(ip, mac, my_ip, load_key())
    if st is None:
        print(f"Kon geen sessie krijgen op {ip} (probeer 'release')."); return 1
    p = paper_present(st.get("C2", b""))
    print(f"PAPIER: {'JA — vel(len) in de lade' if p else 'NEE — lade leeg'}"
          if p is not None else "PAPIER: onbekend")
    return 0 if p else 2

def cmd_scan(args):
    ip = _resolve_ip(args)
    if not ip: return 1
    key = load_key()
    if not key:
        print("Geen pairing-key. Draai eerst 'scansnap pair'."); return 1
    my_ip = local_ip_toward(ip); mac, _ = wifi_mac_toward(ip)
    if not args.force:
        st = read_status(ip, mac, my_ip, key)
        if st and paper_present(st.get("C2", b"")) is False:
            print("Lade is leeg — leg papier in de scanner (of gebruik --force)."); return 2
    print(f"Scannen via {ip}...")
    try:
        pages = scan(ip, key, verbose=args.debug)
    except RuntimeError as e:
        print(f"Fout: {e}"); return 1
    if not pages:
        print("Geen pagina's ontvangen."); return 1
    if args.jpeg:
        os.makedirs("scans", exist_ok=True)
        base = (args.output or "scan").rsplit(".", 1)[0]
        for i, jp in enumerate(pages):
            fn = f"scans/{base}_p{i+1}.jpg"
            with open(fn, "wb") as f: f.write(jp)
            print(f"  opgeslagen {fn} ({len(jp)} bytes)")
    else:
        out = args.output or time.strftime("scan_%Y%m%d_%H%M.pdf")
        _write_pdf(pages, out, lambda d: _jpeg_dims(d))
        print(f"  opgeslagen {out} ({len(pages)} pagina's)")
    return 0

def _jpeg_dims(data):
    i = 2
    while i < len(data) - 9:
        if data[i] != 0xFF:
            i += 1; continue
        m = data[i + 1]
        if 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC):
            return (struct.unpack(">H", data[i + 7:i + 9])[0],
                    struct.unpack(">H", data[i + 5:i + 7])[0])
        i += 2 + struct.unpack(">H", data[i + 2:i + 4])[0]
    return 2480, 3508

def cmd_release(args):
    ip = _resolve_ip(args)
    if not ip: return 1
    my_ip = local_ip_toward(ip); mac, _ = wifi_mac_toward(ip)
    ok = grab_session(ip, mac, my_ip, load_key(), tries=args.rounds, verbose=True)
    if ok:
        d6_release(ip, mac)
        print("✓ sessie vrij."); return 0
    print("✗ nog vergrendeld. Zet WiFi op de Mac uit en probeer opnieuw."); return 1

def cmd_listen(args):
    print("Luisteren op 53220 (Ctrl-C om te stoppen)...")
    try:
        while True:
            for d in passive_listen(5):
                print(f"  broadcast van {d['ip']} (mac {d['mac']})")
    except KeyboardInterrupt:
        print("\ngestopt.")
    return 0

def main():
    ap = argparse.ArgumentParser(prog="scansnap", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("discover", help="find scanners on the /24")
    d.add_argument("--timeout", type=float, default=0.5)
    d.add_argument("--listen", type=float, default=2.0)
    d.set_defaults(func=cmd_discover)

    for name, fn, hlp in [("info", cmd_info, "device info"),
                          ("status", cmd_status, "session state"),
                          ("paper", cmd_paper, "paper in tray?"),
                          ("release", cmd_release, "clear session lock")]:
        p = sub.add_parser(name, help=hlp)
        p.add_argument("-s", "--scanner", dest="scanner", help="scanner IP")
        p.add_argument("ip", nargs="?", help="scanner IP (positional)")
        p.set_defaults(func=fn)
        if name == "release":
            p.add_argument("--rounds", type=int, default=8)

    sc = sub.add_parser("scan", help="scan -> PDF")
    sc.add_argument("-s", "--scanner", dest="scanner", help="scanner IP")
    sc.add_argument("-o", "--output", help="output file")
    sc.add_argument("--jpeg", action="store_true", help="save JPEGs instead of PDF")
    sc.add_argument("--force", action="store_true", help="skip paper check")
    sc.add_argument("-d", "--debug", action="store_true")
    sc.set_defaults(func=cmd_scan)

    pr = sub.add_parser("pair", help="capture pairing key (fake-scanner trick)")
    pr.add_argument("--name", default="iX500",
                    help="fake scanner name; some setups need the full model-serial, "
                         "e.g. iX500-A0PBXXXXXX (check the label on your scanner)")
    pr.set_defaults(func=cmd_pair)
    sub.add_parser("listen", help="watch 53220 broadcasts").set_defaults(func=cmd_listen)

    args = ap.parse_args()
    sys.exit(args.func(args))

if __name__ == "__main__":
    main()
