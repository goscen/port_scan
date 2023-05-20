import socket
import sys
import threading

ports = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 43: "WHOIS", 53: "DNS", 80: "http",
    115: "SFTP", 123: "NTP", 143: "IMAP", 161: "SNMP",
    179: "BGP", 443: "HTTPS", 465: "SMTP", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
}

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
            s.settimeout(3)
            try:
                # connect сканирование
                s.connect((self.destination, port))
            except:
                lock.acquire()
                self._closed_ports += 1
                lock.release()
            else:
                lock_for_ports.acquire()
                self._open_ports[port] = "open"
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
            s.settimeout(3)
            try:
                for i in range(10):
                    s.connect((socket.gethostbyname(self.destination), port))
                    s.sendto(b"", (self.destination, port))
                    data, _ = s.recvfrom(1024)
                    if data is not None:
                        lock_for_ports.acquire()
                        self._open_ports[port] = "open"
                        lock_for_ports.release()
            except socket.error as e:
                lock.acquire()
                self._closed_ports += 1
                lock.release()
            s.close()

    def print_ports_tcp(self):
        self._open_ports = dict(sorted(self._open_ports.items(), reverse=False))
        print(f"Closed ports: {self._closed_ports}")
        for i, v in self._open_ports.items():
            print(f"TCP {i}: {v}")

    def print_ports_udp(self):
        self._open_ports = dict(sorted(self._open_ports.items(), reverse=False))
        print(f"Closed ports: {self._closed_ports}")
        for i, v in self._open_ports.items():
            print(f"UDP {i}: {v}")


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
