#!/usr/bin/env python3
import socket
import argparse
import argparse_parent_base
from multiprocessing import Pool
import time
from printer import Printer
from misc import read_host_from_file, valid_port


class Scanner():

    def __init__(self):
        self.timeout = 1
        socket.setdefaulttimeout(self.timeout)
        self.open_ports = []
        # Ports from 1-1024 (default,if not specified)
        self.ports = range(1, 1025)
        self.ips = []
        self.number_of_process = 10

    def scan(self, args):
        host, port = args
        try:
            # Create a TCP socket and try to connect
            # AF_INET for ipv4,AF_INET6 for ipv6
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            sock.close()
            return host, port, True
        except (socket.timeout, socket.error):
            return host, port, False

    def start(self):
        pool = Pool(processes=self.number_of_process)
        for ip in self.ips:
            for host, port, status in pool.imap_unordered(self.scan, [(ip, port) for port in self.ports]):
                if status:
                    self.open_ports.append(
                        "ip:{0}->port:{1} is open".format(host, port))


def banner():
    banner_txt = """
  _ __   ___  _ __| |_ ___  ___ __ _ _ __  _ __   ___ _ __ 
 | '_ \ / _ \| '__| __/ __|/ __/ _` | '_ \| '_ \ / _ \ '__|
 | |_) | (_) | |  | |_\__ \ (_| (_| | | | | | | |  __/ |   
 | .__/ \___/|_|   \__|___/\___\__,_|_| |_|_| |_|\___|_|   
 |_|                                                       

"A simple port scanner use tcp scan",Check status of given port
Author:Samray <samrayleung@gmail.com>
More Info:python3 tcp_scan.py -h
"""
    print(banner_txt)


def main():
    parser = argparse.ArgumentParser(
        parents=[argparse_parent_base.parser],
        description=banner(),
        add_help=True)
    args = parser.parse_args()
    scanner = Scanner()
    printer = Printer()
    if args.timeout:
        scanner.timeout = args.timeout
    if args.number_of_process:
        scanner.number_of_process = args.number_of_process
    if args.ports:
        ports = map(int, args.ports)
        scanner.ports = filter(valid_port, ports)
    if args.host_file:
        scanner.ips = read_host_from_file(args.host_file)
    scanner.ips += args.host
    scanner.start()
    if args.output_file:
        printer.filepath = args.output_file
        printer.list_to_file(scanner.open_ports)
    else:
        printer.list_to_console(scanner.open_ports)

if __name__ == "__main__":
    start_time = time.time()
    main()
    print("---%s seconds ---" % (time.time() - start_time))
