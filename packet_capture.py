#!/usr/bin/env python
# MIT License
# 
# Copyright (c) 2017 Packt
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# This script creates an  AF_PACKET socket on the interface which is specified as its only argument.
# The purpose is not to write a full packet capture tool. Instead, I wrote it specifically to visualize
# the stack Ethernet/IPv4/GRE/IPv4/TCP for a problem where I encountered partial checksums for GRO
# offloaded packets.
# Usage:
#     python3 packet_capture.py <interface name>
# 
# This script heavily borrows from code found at the following resources:
# https://github.com/PacktPublishing/Python-Penetration-Testing-Cookbook/blob/master/Chapter07/basic-packet-sniffer-linux.py
# https://www.uv.mx/personal/angelperez/files/2018/10/sniffers_texto.pdf
# https://www.binarytides.com/raw-socket-programming-in-python-linux/
# https://dev.to/cwprogram/python-networking-tcp-and-udp-4i3l#tcp-checksum

import socket
import struct
import sys
from copy import deepcopy

#################
# Constants
#################

ETH_P_ALL = 3
TCP = 6
GRE = 47
IPv4 = 0x800
ETHERNET=0x0

#################
# Functions
#################

def get_mac_addr(mac_raw):
    """
    get_mac_addr takes a 6 Byte array and formats it to MAC address representation.

    :param mac_raw: 6 Byte array holding a MAC address.
    :return: String represetnation of the MAC address.
    """
    if len(mac_raw) != 6:
        return "00:00:00:00:00:00"
    byte_str = map('{:02x}'.format, mac_raw)
    mac_addr = ':'.join(byte_str)
    return mac_addr

def get_ip(addr):
    """
    get_ip  takes a 4 Byte array and formats it to IPv4 representation.

    :param addr: 4 Byte array holding an IPv4 address.
    :return: String representation of the IPv4 address.
    """
    if len(addr) != 4:
        return "0.0.0.0"
    return '.'.join(map(str, addr))

def ethernet_head(raw_data):
    """
    ethernet_head receives raw packet data and interprets it as an Ethernet header.

    :param raw_data: Byte array holding an Ethernet frame with payload.
    :returns:
        - dest_mac - Destination MAC address
        - src_mac - Source MAC address
        - ethertype - Ethertype of payload, e.g. 0x800 for IPv4
        - header The - header of this Ethernet packet
        - payload - The payload of this Ethernet packet, typically IP
    """
    header = raw_data[:14]
    dest, src, ethertype = struct.unpack('! 6s 6s H', header)
    dest_mac = get_mac_addr(dest)
    src_mac = get_mac_addr(src)
    payload = raw_data[14:]
    return dest_mac, src_mac, ethertype, header, payload


def ipv4_head(raw_data):
    """
    ipv4_head receives raw packet data and interprets it as an IPv4 header.

    :param raw_data: Byte array holding an IPv4 packet with payload.
    :returns:
        - version - IP version
        - header_length - IP header lenght
        - ttl - IPv4 header length
        - proto - Protocol number of next protocol, e.g. 6 for TCP, 47 for GRE
        - checksum - IPv4 checksum
        - src - IPv4 source address
        - dest - IPv4 dest address
        - header - IPv4 header
        - payload - IPv4 payload
    """
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, checksum, src, target = struct.unpack('! 8x B B H 4s 4s', raw_data[:20])
    header = raw_data[:header_length]
    payload = raw_data[header_length:]
    return version, header_length, ttl, proto, checksum, get_ip(src), get_ip(target), header, payload

def gre_head(raw_data):
    """
    gre_head receives raw packet data and interprets it as a GRE header.

    :param raw_data: Byte array holding an GRE packet with payload.
    :returns:
        - prototype - Ethertype of next protocol, e.g. 0x800 for IPv4
        - header - GRE header
        - payload - GRE payload
    """
    header = raw_data[:4]
    payload = raw_data[4:]
    prototype, = struct.unpack('! 2x H', header)
    return prototype, header, payload


def tcp_head(raw_data):
    """
    tcp_head receives raw packet data and interprets it as a TCP header.

    :param raw_data: Byte array holding a TCP packet with payload.
    :returns:
        - src_port
        - dest_port
        - sequence
        - acknowledgment
        - flag_urg
        - flag_ack
        - flag_psh
        - flag_rst
        - flag_syn
        - flag_fin
        - window
        - checksum
        - header - TCP header
        - payload - TCP payload
    """
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags, window, checksum) = struct.unpack('! H H L L H H H', raw_data[:18])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    header = raw_data[:offset]
    payload = raw_data[offset:]
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, window, checksum, header, payload


def print_protocol(data, previous_header=None, offset="", ethertype=None, internet_protocol=None):
    """
    print_protocol receives input which is important to print the current layer of the TCP/IP stack and prints it.
    It then returns the current header, payload, next ethertype respectively the next IP protocol type so that the next
    invocation of print_protocol can print the next layer of the TCP/IP stack.
    
    :param data: Byte array holding the current layer of the TCP/IP stack.
    :param previous_header: Byte array holding the header of the previous layer of the TCP/IP stack. E.g., if this layer
                            is TCP, it will hold the IP header.
    :param offset: Offset that's used when printing output.
    :param ethertype: Ethertype of the next protocol.
    :param internet_protocol: IP protocol number of the next protocol.
                            
    :returns:
        - header - The header of the current layer of the TCP/IP stack
        - payload - Payload containing the next layer of the TCP/IP stack
        - next_ethertype - The Ethertype of the next layer of the TCP/IP stack
        - next_internet_protocol - The Internet Protocol number of the next layer of the TCP/IP stack
    """
    # Ethernet
    if ethertype == ETHERNET:
        dest_mac, src_mac, next_ethertype, header, data = ethernet_head(data)
        print(f'{offset}{src_mac} -> {dest_mac}, ethertype: {hex(next_ethertype)}, len: {len(data)}')
        return header, data, next_ethertype, None
    # IP
    if ethertype == IPv4:
        version, header_length, ttl, next_internet_protocol, checksum, src, target, header, payload = ipv4_head(data)
        print(f'{offset}version: {version}, header len: {header_length}, ttl: {ttl}, proto: {next_internet_protocol}, checksum: {hex(checksum)}, src: {src}, dest: {target}')
        return header, payload, None, next_internet_protocol
    # TCP
    if internet_protocol == TCP:
        src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, window, header_checksum, tcp_header, tcp_payload = tcp_head(data)
        print(f'{offset}src_port: {src_port}, dest_port: {dest_port}, sequence: {sequence}, checksum: {hex(header_checksum)}')
        pseudo_header, tcp_header_without_checksum = tcp_pseudo_header(previous_header, tcp_header, tcp_payload)
        calculated_checksum = calculate_checksum(pseudo_header + tcp_header_without_checksum + tcp_payload)
        print(f'{offset}calculated_checksum: {hex(calculated_checksum)}')
        return tcp_header, tcp_payload, None, None
    # GRE
    if internet_protocol == GRE:
        next_ethertype, header, payload = gre_head(data)
        print(f'{offset}gre ethertype: {hex(next_ethertype)}')
        return header, payload, next_ethertype, None
    # return header, data, next_ethertype, next_internet_protocol
    return None, None, None, None

def calculate_checksum(msg):
    """
    calculate_checksum calculates the TCP checksum for the provided data.
    Copied from: https://www.binarytides.com/raw-socket-programming-in-python-linux/
    
    :param msg: Byte array for which the checksum will be calculated.
                            
    :return: TCP checksum for the provided input
    """
    s = 0
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
    	w = msg[i] + (msg[i+1] << 8 )
    	s = s + w
    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);
    #complement and mask to 4 byte short
    s = ~s & 0xffff
    return socket.htons(s)

def tcp_pseudo_header(ip_header, tcp_header, tcp_payload):
    """
    tcp_pseudo_header takes an IP header, TCP header and TCP payload and returns the IPv4 pseudo header and the TCP
    header with the checksum fields set to all 0s.
     calculates the TCP checksum for the provided data.
    https://dev.to/cwprogram/python-networking-tcp-and-udp-4i3l#tcp-checksum
    
    :param ip_header: Byte representation of the IPv4 header.
    :param tcp_header: Byte representation of the TCP header.
    :param tcp_payload: Byte representation of the TCP payload.
                            
    :returns:
        - pseudo_header - pseudo header (https://datatracker.ietf.org/doc/html/rfc9293#v4pseudo)
        - header_without_checksum - TCP header with the checksum fields set to all 0s
    """
    ttl, proto, checksum, src, target = struct.unpack('! 8x B B H 4s 4s', ip_header[:20])
    header_without_checksum = bytearray(deepcopy(tcp_header))
    header_without_checksum[16] = 0x0
    header_without_checksum[17] = 0x0
    pseudo_header = struct.pack('!4s4sHH', src, target, socket.IPPROTO_TCP, len(tcp_header) + len(tcp_payload))
    return pseudo_header, header_without_checksum

#################
# main
#################

def main() -> int:
    """
    main creates a socket for family AF_PACKET of type SOCK_RAW. It will bind to interface argv[1].
    This kind of socket creates a copy for each packet on the Ethernet layer, just as the packet is received.
    One copy is sent to the socket, the other socket continues is processed as normally.
    For further information, see:
    https://stackoverflow.com/questions/62866943/how-does-the-af-packet-socket-work-in-linux
    https://man7.org/linux/man-pages/man7/packet.7.html

    main then does a blocking recv on the socket. When a packet is received, it will first interpret it as an Ethernet
    frame. Subsequently, it will try to interpret the packet until print_protocol returns None for both ethertype and
    internet_protocol. Each layer of the TCP/IP stack will be printed with an additional indentation of "    ".
    This script currently can interpret Ethernet, IPv4, GRE and TCP. So execution should stop with any payload which is
    neither of the aforementioned protocols.
    Once the current packet cannot be processed further, main will wait for the next packet to arrive. The logic will then
    repeat.
    """
    if len(sys.argv) < 2:
        print("Provide a valid interface name to bind to")
        return 1
    intf = sys.argv[1]

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((intf, 0))
    while True:
        offset = ""
        response = s.recv(65565)
        # Ethernet
        header, payload, ethertype, internet_protocol = print_protocol(data=response, ethertype=ETHERNET)
        while ethertype != None or internet_protocol != None:
            offset += "    "
            header, payload, ethertype, internet_protocol = print_protocol(
                    data=payload, previous_header=header, ethertype=ethertype, internet_protocol=internet_protocol, offset=offset)
    s.close()

if __name__ == '__main__':
    sys.exit(main())
