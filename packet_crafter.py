import struct


def dns_packet() -> bytes:
    pack_id = struct.pack('!H', 20)
    flags = struct.pack('!H', 256)
    qd_count = struct.pack('!H', 1)
    an_count = struct.pack('!H', 0)
    ns_count = struct.pack('!H', 0)
    ar_count = struct.pack('!H', 0)
    header = pack_id + flags + qd_count + an_count + ns_count + ar_count
    domain = 'example.ru'
    sec_dom, first_dom = domain.split('.')
    mark_first = struct.pack('!H', len(sec_dom))
    byte_sec = struct.pack(f'!{len(sec_dom)}s', sec_dom.encode())
    mark_second = struct.pack('!H', 2)
    byte_first = struct.pack(f'!{len(first_dom)}s', first_dom.encode())
    q_type = struct.pack('!H', 1)
    q_class = struct.pack('!H', 1)
    packet = header + mark_first + byte_sec + mark_second + byte_first \
             + struct.pack('!H', 0) + q_type + q_class
    return packet


def ntp_packet():
    ntp_request = bytearray(48)
    ntp_request[0] = 0x1B
    return ntp_request


def http_packet():
    return b"GET / HTTP/1.1\r\n\r\n"


def whois_packet():
    return b"google.com\r\n"


def craft_tcp_packets():
    packets = [http_packet(), whois_packet(), b""]
    return packets


def craft_udp_packets():
    packets = [ntp_packet(), dns_packet(), b""]
    return packets
