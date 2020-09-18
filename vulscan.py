#!/usr/bin/python3

from socket import *
import sys
import os
from termcolor import colored

def checkvuln(banner ,filename):
    with open(filename , "r") as f:
        for line in f.readlines():
            if line.strip("\n") in banner:
                print(colored("[+] Server is vulnerable : " + banner.strip("\n"),"green"))

def ret_banner(ip,port):
    try:
        sock = socket()
        sock.setdefaulttimeout(2)
        sock.connect((ip,port))
        banner = sock.recv(1024)
        return banner
    except:
        return

def main():
    if len(sys.argv) == 2:
        filename = sys.argv[1]
        if not os.path.isfile(filename):
            print(colored("[-] File "+filename +" Not Found","red"))
            exit(0)
        if not os.access(filename, os.R_ok):
            print(colored("[-] Access Denied","Red"))
            exit(0)
    else:
        print(colored("Usage: "+str(sys.argv[0]) +" <vul filename>","yellow"))
        exit(0)

    portlist = [22,23,25,80,443,512]
    for x in range(132,136):
        ip = "192.168.32." + str(x)
        for port in portlist:
            banner = ret_banner(ip,port)
            if banner:
                print(colored("[+] "+ip + "/"+str(port)+":"+str(banner),"green"))
                checkvuln(banner , flename)

if __name__ == '__main__':
    main()

