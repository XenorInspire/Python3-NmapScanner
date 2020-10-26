#!/usr/bin/env python3

import collections
import nmap
scanner = nmap.PortScanner()
ScanType = collections.namedtuple("ScanType", "proto args")
scan_types = {
    1: ScanType(proto="tcp", args="-v -sS"),
    2: ScanType(proto="udp", args="-v -sU"),
    3: ScanType(proto="tcp", args="-v -sS -sV -sC -A -O")
}


def ipAddr():
    ip_addr = input("Please enter the IP address you want to scan: ")
    print("The IP you entered is: ", ip_addr)
    return ip_addr


def main():
    print("<= == == == == == == == == === >")
    print("       Python-NmapScanner")
    print("<= == == == == == == == == === >\n")
    print("This script requires root privileges")
    resp = -1

    while(resp != 0):

        resp = input(
            "\nWhat do you want to do ?\n\n1) SYN ACK Scan\n2) UDP Scan\n3) Comprehensive Scan\n0) Exit\n")

        try:
            resp = int(resp)

        except ValueError:
            resp = 4

        if resp in scan_types:

            ip_addr = ipAddr()
            scan_type = scan_types[resp]

            "Nmap Version: ", scanner.nmap_version()
            scanner.scan(ip_addr, '1-1024', scan_type.args)
            print(scanner.scaninfo())
            print("IP Status: ", scanner[ip_addr].state())
            print("Protocols: ", ", ".join(scanner[ip_addr].all_protocols()))
            print("Open Ports: ", ", ".join(str(p) for p in scanner[ip_addr][scan_type.proto].keys()))

main()
