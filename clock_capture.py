"""Collect a read-only NTP sample and read Windows certificate validity dates."""

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re
import socket
import struct
import sys
import time


NANOSECONDS = 1_000_000_000
NTP_EPOCH = 2_208_988_800
NTP_ERA = 1 << 32
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
PEM_CERT = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\s]+?)"
    rb"\s*-----END CERTIFICATE-----"
)


@dataclass(frozen=True)
class ClockSample:
    client_time: datetime
    server_time: datetime
    round_trip_us: int
    uncertainty_us: int


def ntp_timestamp(utc_ns):
    seconds, fraction = divmod(utc_ns, NANOSECONDS)
    return struct.pack("!II", (seconds + NTP_EPOCH) % NTP_ERA, fraction * NTP_ERA // NANOSECONDS)


def timestamp_ns(wire, near_ns):
    seconds, fraction = struct.unpack("!II", wire)
    near = near_ns // NANOSECONDS + NTP_EPOCH
    era = (near - seconds + NTP_ERA // 2) // NTP_ERA
    return (era * NTP_ERA + seconds - NTP_EPOCH) * NANOSECONDS + fraction * NANOSECONDS // NTP_ERA


def utc_from_ns(value):
    return UNIX_EPOCH + timedelta(microseconds=value // 1000)


def parse_ntp_reply(packet, sent_ns, received_ns):
    if len(packet) < 48:
        raise ValueError("short NTP response")
    leap = packet[0] >> 6
    version = (packet[0] >> 3) & 7
    mode = packet[0] & 7
    if mode != 4 or version not in (3, 4):
        raise ValueError("response must be an NTP version 3 or 4 server reply")
    if leap == 3 or not 1 <= packet[1] <= 15:
        raise ValueError("NTP server is unsynchronized or refused the request")
    if packet[24:32] != ntp_timestamp(sent_ns):
        raise ValueError("NTP reply does not match the request timestamp")
    if not any(packet[32:40]) or not any(packet[40:48]):
        raise ValueError("NTP reply is missing server timestamps")

    server_received = timestamp_ns(packet[32:40], sent_ns)
    server_sent = timestamp_ns(packet[40:48], sent_ns)
    processing = server_sent - server_received
    delay = (received_ns - sent_ns) - processing
    if processing < 0 or delay < 0:
        raise ValueError("inconsistent NTP timing values")

    offset = ((server_received - sent_ns) + (server_sent - received_ns)) // 2
    root_delay, dispersion = struct.unpack_from("!iI", packet, 4)
    upstream = (max(root_delay, 0) + 2 * dispersion) * NANOSECONDS // (2 * 65536)
    # Include the sample's network delay, the server's upstream margin and rounding.
    return ClockSample(
        client_time=utc_from_ns(received_ns),
        server_time=utc_from_ns(received_ns + offset),
        round_trip_us=(delay + 999) // 1000,
        uncertainty_us=((delay + 1) // 2 + upstream + 999) // 1000 + 1,
    )


def probe_clock(host, port=123, timeout=2.0):
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    last_error = None
    requested = set()
    for family, kind, protocol, _, address in addresses:
        if (family, address) in requested:
            continue
        requested.add((family, address))
        try:
            with socket.socket(family, kind, protocol) as sock:
                sock.settimeout(timeout)
                sock.connect(address)
                request = bytearray(48)
                request[0] = 0x23  # NTPv4 client
                before = time.monotonic_ns()
                sent = time.time_ns()
                request[40:48] = ntp_timestamp(sent)
                sock.send(request)
                packet = sock.recv(1024)
                received = time.time_ns()
                after = time.monotonic_ns()
            if abs((received - sent) - (after - before)) > 100_000_000:
                raise ValueError("local wall clock changed during the NTP exchange")
            return parse_ntp_reply(packet, sent, received)
        except (OSError, ValueError) as exc:
            last_error = exc
    raise ValueError(f"could not read an NTP sample from {host} on UDP port {port}: {last_error or 'no addresses'}")


def certificate_der(raw):
    if raw.lstrip().startswith(b"-----"):
        match = PEM_CERT.fullmatch(raw.strip())
        if not match:
            raise ValueError("provide a single PEM certificate or a DER certificate")
        try:
            return base64.b64decode(b"".join(match[1].split()), validate=True)
        except ValueError as exc:
            raise ValueError("the PEM certificate contains invalid base64") from exc
    return raw


def read_certificate_validity(path):
    if sys.platform != "win32":
        raise ValueError("certificate file import uses Windows CryptoAPI; use dates in an evidence file on other platforms")
    data = certificate_der(path.read_bytes())
    if not data:
        raise ValueError("the certificate file is empty")

    import ctypes as c
    from ctypes.wintypes import BOOL, DWORD, FILETIME

    class Blob(c.Structure):
        _fields_ = [("length", DWORD), ("data", c.c_void_p)]

    class Algorithm(c.Structure):
        _fields_ = [("oid", c.c_void_p), ("parameters", Blob)]

    class CertInfo(c.Structure):
        # This is the documented prefix through the last field used here.
        _fields_ = [
            ("version", DWORD), ("serial", Blob), ("algorithm", Algorithm),
            ("issuer", Blob), ("not_before", FILETIME), ("not_after", FILETIME),
        ]

    class CertContext(c.Structure):
        _fields_ = [
            ("encoding", DWORD), ("bytes", c.c_void_p), ("length", DWORD),
            ("info", c.POINTER(CertInfo)), ("store", c.c_void_p),
        ]

    crypt = c.WinDLL("crypt32", use_last_error=True)
    create = crypt.CertCreateCertificateContext
    create.argtypes = [DWORD, c.c_void_p, DWORD]
    create.restype = c.POINTER(CertContext)
    free = crypt.CertFreeCertificateContext
    free.argtypes = [create.restype]
    free.restype = BOOL
    context = create(1, c.create_string_buffer(data), len(data))  # X509_ASN_ENCODING
    if not context:
        raise ValueError(f"Windows could not read the X.509 certificate (error 0x{c.get_last_error():08X})")
    filetime_epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)

    def as_utc(value):
        ticks = (value.dwHighDateTime << 32) | value.dwLowDateTime
        return filetime_epoch + timedelta(microseconds=ticks // 10)

    try:
        info = context.contents.info.contents
        return as_utc(info.not_before), as_utc(info.not_after)
    finally:
        free(context)
