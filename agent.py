#!/usr/bin/env python3
import sys
import logging
import netifaces
import signal
from re import match
from threading import Timer
from match import match_client, match_server
from hijack import start_hijack, stop_hijack

logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # Suppress scapy ipv6 error
from scapy.all import sniff, Ether, IP, TCP

###############################
# Constants
###############################

DEFAULT_HIJACK_WAIT_TIME = 3

###############################
# Helper classes / methods
###############################

class Hijacker:
    def __init__(self, client_pkt):
        """Extracts client_pkt to determine target"""
        self.client_mac  = client_pkt[Ether].src
        self.client_ip   = client_pkt[IP].src
        # Discard client port; not going to use it
        # because we want to recognise new connections (w/ different srcports) too
        self.server_mac  = client_pkt[Ether].dst
        self.server_ip   = client_pkt[IP].dst
        self.server_port = client_pkt[TCP].dport

        self.listen_intf = listen_intf

        self.response_detected = False
        self.timer = None
        self.hijacking = False

    def is_client_pkt(self, pkt):
        return (
            pkt[Ether].src == self.client_mac and pkt[IP].src == self.client_ip
            and pkt[Ether].dst == self.server_mac and pkt[IP].dst == self.server_ip and pkt[TCP].dport == self.server_port
        )

    def is_server_pkt(self, pkt):
        return (
            pkt[Ether].src == self.server_mac and pkt[IP].src == self.server_ip and pkt[TCP].sport == self.server_port
            and pkt[Ether].dst == self.client_mac and pkt[IP].dst == self.client_ip
        )

    def update_timer(self, hijack_wait_time):
        """
        Will call self.start() after hijack_wait_time has passed. Resets timer on every call.
        Does NOT check if self.start() was called before!
        """
        if self.timer:
            self.timer.cancel()
        self.timer = Timer(hijack_wait_time, self.start)
        self.timer.start()

    def start(self):
        print("Starting hijack")
        self.hijacking = True
        start_hijack(self)

    def stop(self):
        print("Stopping hijack")
        self.hijacking = False
        stop_hijack(self)

def on_packet(packet):
    global target, hijack_wait_time

    if target == None:
        if match_client(packet):
            print("-- Detected client request!")
            target = Hijacker(packet)
        return

    if not target.response_detected:
        if target.is_server_pkt(packet) and match_server(packet):
            print("-- Detected server response!")
            target.response_detected = True
            target.update_timer(hijack_wait_time)
        return

    if not target.hijacking and (target.is_client_pkt(packet) or target.is_server_pkt(packet)):
        target.update_timer(hijack_wait_time)

def handle_sigint(signal, frame):
    if target != None and target.hijacking:
        target.stop()
    sys.exit(0)

###############################
# Main program
###############################

# Validate arguments length
if len(sys.argv) < 2 or len(sys.argv) > 3:
    print("Usage: " + sys.argv[0] + " listen_intf [hijack_wait_sec]")
    sys.exit(1)

# Validate input
if sys.argv[1] not in netifaces.interfaces():
    print("Listen interface not found in interfaces list")
    sys.exit(1);

target = None
listen_intf = sys.argv[1];
hijack_wait_time = DEFAULT_HIJACK_WAIT_TIME

if len(sys.argv) == 4:
    if sys.argv[2].isdigit():
        hijack_wait_time = int(sys.argv[2])
    else:
        print("Invalid wait time, defaulting to " + DEFAULT_HIJACK_WAIT_TIME)

signal.signal(signal.SIGINT, handle_sigint)

sniff(iface=listen_intf, filter="tcp", store=0, prn=on_packet)
