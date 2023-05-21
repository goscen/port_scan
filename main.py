import socket
import sys
import threading

import packet_crafter

lock = threading.Lock()
lock_for_ports = threading.Lock()


class Scanner:
    def __init__(self, dest, type_of_scan, begin, end):
        self.destination = dest
        self.type_of_scan = type_of_scan
        self.begin = int(begin)
        self.end = int(end)
        self._closed_ports = 0
        self._threads = 10
        self._open_ports = {}

    def start_scan(self):
        if self.type_of_scan == "-t":
            self.start_tcp_scan()
        elif self.type_of_scan == "-u":
            self.start_udp_scan()
        else:
            print("Bad type of protocol only tcp/udp(-t/-u)")

    def start_tcp_scan(self):
        number_of_ports = self.end - self.begin
        add = number_of_ports // self._threads
        if add == 0:
            self._threads = number_of_ports
        start = 1
        end_for_thread = start + add
        pool = []
        for i in range(0, self._threads - 1):
            thread = threading.Thread(target=self.tcp_scan, args=(start, end_for_thread))
            thread.start()
            start = end_for_thread
            end_for_thread += add
            pool.append(thread)
        else:
            thread = threading.Thread(target=self.tcp_scan, args=(start, self.end + 1))
            thread.start()
            pool.append(thread)
        for t in pool:
            t.join()
        self.print_ports_tcp()

    def tcp_scan(self, begin_for_thread, end_for_thread):
        for port in range(begin_for_thread, end_for_thread):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            protocol = None
            try:
                # connect сканирование
                s.connect((self.destination, port))
                try:
                    data, _ = s.recvfrom(1024)
                    protocol = self.recognize_port_tcp(data)
                except:
                    packets = packet_crafter.craft_tcp_packets()
                    for packet in packets:
                        s.sendto(packet, (self.destination, port))
                        data, _ = s.recvfrom(1024)
                        protocol = self.recognize_port_tcp(data)
                        if protocol is not None:
                            break

            except:
                lock.acquire()
                self._closed_ports += 1
                lock.release()
            else:
                lock_for_ports.acquire()
                self._open_ports[port] = protocol
                lock_for_ports.release()
            s.close()

    def start_udp_scan(self):
        number_of_ports = self.end - self.begin
        add = number_of_ports // self._threads
        if add == 0:
            self._threads = number_of_ports
            add = 1
        start = 1
        end_for_thread = start + add
        pool = []
        for i in range(0, self._threads - 1):
            thread = threading.Thread(target=self.udp_scan, args=(start, end_for_thread))
            thread.start()
            start = end_for_thread
            end_for_thread += add
            pool.append(thread)
        else:
            thread = threading.Thread(target=self.udp_scan, args=(start, self.end + 1))
            thread.start()
            pool.append(thread)
        for t in pool:
            t.join()
        self.print_ports_udp()

    def udp_scan(self, begin_for_thread, end_for_thread):
        for port in range(begin_for_thread, end_for_thread):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            try:
                # посылаем udp пакет 3 раза
                for i in range(3):
                    for packet in packet_crafter.craft_udp_packets():
                        s.sendto(packet, (self.destination, port))
                        data, _ = s.recvfrom(1024)
                        if data is not None:
                            protocol = self.recognize_port_udp(data)
                            lock_for_ports.acquire()
                            self._open_ports[port] = protocol
                            self._closed_ports -= 1
                            lock_for_ports.release()
            except socket.error:
                lock.acquire()
                self._closed_ports += 1
                lock.release()
            s.close()

    def print_ports_tcp(self):
        self._open_ports = dict(sorted(self._open_ports.items(), reverse=False))
        print(f"Closed ports: {self._closed_ports}")
        for i, v in self._open_ports.items():
            if v is not None:
                print(f"TCP {i}: {v}")
            else:
                print(f"TCP {i}")

    def print_ports_udp(self):
        self._open_ports = dict(sorted(self._open_ports.items(), reverse=False))
        print(f"Closed ports: {self._closed_ports}")
        for i, v in self._open_ports.items():
            if v is not None:
                print(f"UDP {i}: {v}")
            else:
                print(f"UDP {i}")

    def recognize_port_tcp(self, data):
        pop3_signature = b"+OK\r\n"
        smtp_signature = b"220"
        ssh_signature = b"SSH"
        http_signature = b"HTTP/1.1"
        whois_signature = b"% "
        if data.startswith(pop3_signature):
            return "POP3"
        elif data.startswith(smtp_signature):
            return "SMTP"
        elif data.startswith(ssh_signature):
            return "SSH"
        elif data.startswith(http_signature):
            return "HTTP"
        elif data.startswith(whois_signature):
            return "WHOIS"

    def recognize_port_udp(self, data):
        ntp_signature = b"\x1c"
        dns_signature = b"\x00\x07exa"

        if data.endswith(dns_signature):
            return "DNS"
        elif data.startswith(ntp_signature):
            return "NTP"


if __name__ == "__main__":
    if len(sys.argv) < 6:
        print("Args: destination -t/-u(tcp or udp scan) -p/--port N1 N2(range of ports)")
        sys.exit()
    dest = sys.argv[1]
    type_of_scan = sys.argv[2]
    begin = sys.argv[4]
    end = sys.argv[5]
    scaner = Scanner(dest, type_of_scan, begin, end)
    scaner.start_scan()
