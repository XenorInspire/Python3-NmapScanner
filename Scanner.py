#!/usr/bin/env python

import nmap
scanner = nmap.PortScanner()


def ipAddr():
    ip_addr = input("Please enter the IP address you want to scan: ")
    print("The IP you entered is: ", ip_addr)
    return ip_addr


def main():
    print("<= == == == == == == == == === >")
    print("       Python-NmapScanner")
    print("<= == == == == == == == == === >\n")
    print("This script requires root privileges")
    resp = 1

    while(resp != '0'):

        resp = input("\nWhat do you want to do ?\n\n1) SYN ACK Scan\n2) UDP Scan\n3) Comprehensive Scan\n0) Exit\n")

        if resp == '1':

            ip_addr = ipAddr()
            print("Nmap Version: ", scanner.nmap_version())
            scanner.scan(ip_addr, '1-1024', '-v -sS')
            print(scanner.scaninfo())
            print("Ip Status: ", scanner[ip_addr].state())
            print(scanner[ip_addr].all_protocols())
            print("Open Ports: ", scanner[ip_addr]['tcp'].keys())

        elif resp == '2':

            ip_addr = ipAddr()
            print("Nmap Version: ", scanner.nmap_version())
            scanner.scan(ip_addr, '1-1024', '-v -sU')
            print(scanner.scaninfo())
            print("Ip Status: ", scanner[ip_addr].state())
            print(scanner[ip_addr].all_protocols())
            print("Open Ports: ", scanner[ip_addr]['udp'].keys())

        elif resp == '3':

            ip_addr = ipAddr()
            print("Nmap Version: ", scanner.nmap_version())
            scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
            print(scanner.scaninfo())
            print("Ip Status: ", scanner[ip_addr].state())
            print(scanner[ip_addr].all_protocols())
            print("Open Ports: ", scanner[ip_addr]['tcp'].keys())


main()
