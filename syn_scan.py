import prettytable
import argparse
import argparse_parent_base
import time
from printer import Printer
from multiprocessing import Pool, Queue
from misc import read_host_from_file, valid_port

from scapy.all import *
ICMP_TYPE_DESTINATION_UNREACHABLE = 3
ICMP_CODE_HOST_UNREACHABLE = 1
ICMP_CODE_PROTOCAL_UNREACHABLE = 2
ICMP_CODE_PORT_UNREACHABLE = 3
ICMP_CODE = [ICMP_CODE_PORT_UNREACHABLE,
             ICMP_CODE_HOST_UNREACHABLE, ICMP_CODE_PROTOCAL_UNREACHABLE]


class Scanner():

    def __init__(self):
        self.ips = []
        self.timeout = 1
        self.status_ports = []
        self.ports = range(1, 1025)
        self.number_of_process = 10

    def scan(self, args):
        dst_ip, dst_port = args
        src_port = RandShort()
        answered, unanswered = sr(IP(dst=dst_ip) / TCP(sport=src_port,
                                                       dport=dst_port, flags="S"),
                                  timeout=self.timeout, verbose=False)
        for packet in unanswered:
            return packet.dst, packet.dport, "Filtered"

        for (send, recv) in answered:
            if(recv.haslayer(TCP)):
                flags = recv.getlayer(TCP).sprintf("%flags%")
                if(flags == "SA"):
                    # set RST to server in case of ddos attack
                    send_rst = sr(IP(dst=dst_ip) / TCP(sport=src_port,
                                                       dport=dst_port, flags="R"),
                                  timeout=self.timeout, verbose=True)
                    return dst_ip, dst_port, "Open"
                elif (flags == "RA" or flags == "R"):
                    return dst_ip, dst_port, "Closed"
            elif(recv.haslayer(ICMP)):
                icmp_type = recv.getlayer(ICMP).type
                icmp_code = recv.getlayer(ICMP).code
                if(icmp_type == ICMP_TYPE_DESTINATION_UNREACHABLE and icmp_code in ICMP_CODE):
                    return dst_ip, dst_port, "Filtered"
            else:
                return dst_ip, dst_port, "CHECK"

    def start(self):
        pool = Pool(processes=self.number_of_process)
        for ip in self.ips:
            for host, port, status in pool.imap_unordered(self.scan, [(ip, port) for port in self.ports]):
                self.status_ports.append(
                    "ip:{0}->port:{1} is {2}".format(host, port, status))


def banner():
    banner_txt = """
  _ __   ___  _ __| |_ ___  ___ __ _ _ __  _ __   ___ _ __ 
 | '_ \ / _ \| '__| __/ __|/ __/ _` | '_ \| '_ \ / _ \ '__|
 | |_) | (_) | |  | |_\__ \ (_| (_| | | | | | | |  __/ |   
 | .__/ \___/|_|   \__|___/\___\__,_|_| |_|_| |_|\___|_|   
 |_|                                                       

"A simple port scanner use syn scan",Check status of given port
Author:Samray <samrayleung@gmail.com>
More Info:python3 syn_scan.py -h
"""
    print(banner_txt)


def main():
    parser = argparse.ArgumentParser(parents=[argparse_parent_base.parser],
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
        printer.list_to_file(scanner.status_ports)
    else:
        printer.list_to_console(scanner.status_ports)
if __name__ == "__main__":
    start_time = time.time()
    main()
    print("---%s seconds ---" % (time.time() - start_time))
