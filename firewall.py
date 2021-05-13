import socket
import sys
import matplotlib.pyplot as plt
from os import system
from struct import *
import struct
import select
import time
import numpy as np
import json
import pyfiglet

class SimpleFirewall:
    """This Firewall emulates the scenario on a pre-defined hardcoded set of rules to filter packets. Filter works on only Layer 2(Ethernet) packets"""

    def __init__(self,interface1,interface2):
        self.host1sock = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0003))
        self.extsock = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0003))

        self.host1sock.bind((interface1,0))
        self.extsock.bind((interface2,0))

    def parseEtherHead(self,raw_data):
        dest, src , prototype = struct.unpack("!6s6sH",raw_data[:14])
        destin_mac_addr =  ':'.join('%02x' % b for b in dest)
        src_mac_addr = ':'.join('%02x' % b for b in src)
        prototype_field = socket.htons(prototype)
        return destin_mac_addr,src_mac_addr,prototype_field

    def decideRule(self,raw_data):
        eth = self.parseEtherHead(raw_data)
        if (eth[2] == socket.ntohs(0x0800) and eth[1] == "76:78:a8:1d:1e:7f"):   #Rule1 : Allow IP from external host
            allow = True
            packet_type = "External"
            self.host1sock.sendall(raw_data)

        elif(eth[2] == socket.ntohs(0x0800) and eth[1] == "06:14:ad:b3:69:3d"): #Rule2 : Allow Host1 Packets from host1
            allow = True
            packet_type = "Internal"
            self.host1sock.sendall(raw_data)

        else:                                           #Rule 5: Disallow all external packets
            allow = False
            packet_type = "External"

        return allow,packet_type

    def startFirewall(self):
        print("\u001b[41;1m\t\tSimple Firewall Running...\u001b[0m\n")

        while True:
            all_socks = [self.host1sock,self.extsock]

            ready_socks,_,_ = select.select(all_socks,[],[])
            for soc in ready_socks:
                raw_data,addr = soc.recvfrom(65565)
                ret = self.decideRule(raw_data)
                if(ret[0]):
                    print(u"Packet \u001b[42;1m Allowed\u001b[0m\t Packet Type: ",ret[1])
                else:
                    print(u"Packet \u001b[41;1m Discarded\u001b[0m\t Packet Type: ",ret[1])

'''
The Following Class Represents the Advanced FIrewall for tasks 2,3 and 4 which provides a complete extended set of features as in above simple firewall. This Firewall works across the layers 2,3 and 4 i.e Ethernet, Network and the Transport layer protocols in the network. It provides a complete set of Rule management having ADD, UPDATE, DELETE and VIEW of rules. Has option of saving the rules locally in file and later loading the rules to the system. It also has Statistics Monitor that displays various performance metrics and generates performance plots.

This Class also has mechanism for DoS attack detection for task 4
'''
class AdvancedFirewall():

    def __init__(self, interface1, interface2):
        self.host1sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x003))
        self.extsock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

        #self.host1sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        #self.host2sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        #self.extsock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        self.host1sock.bind((interface1, 0))
        self.extsock.bind((interface2, 0))
        self.all_rules = {"Ether_rules" : [], "IPv4rules" : [], "IPv6rules" : [], "TCPrules" :[], "UDPrules":[],"ICMPrules":[]}
        self.matching_map = {"dest_mac":"" ,"source_mac":"", "ether_proto": 0,"ttl":0,"ipv4protocol":0,"v4source_addr":"","v4dest_addr":"","traffic_class":0,"flow_label":0,"header_len":0,"v6source_addr":"","v6dest_addr":"","tcp_src":0,"tcp_dest":0,"flag_syn":0,"flag_ack":0,"flag_fin":0,"udpsrc_port":0,"udpdest_port":0,"udpdata_len":0,"icmpv4type":0,"icmpv4code":0,"icmpv6type":0,"icmpv6code":0}
        self.packet = ""
        self.times = []
        self.avg_time = 0.0
        self.allowed_pack = []
        self.discarded_pack = []
        self.allowed = 0
        self.discarded = 0
        self.dos_threshold = 0                     #Used to set the DOS IP threshold
        self.dos_track = {}                        #This dictionary keeps track of each source IP pinged by maintaing a count
        self.dos_switch = False
    def parseEtherHead(self,raw_data):
        self.packet = u"\u001b[41;1m[Ethernet]\u001b[0m"
        dest, src , prototype = struct.unpack("!6s6sH",raw_data[:14])
        dest_mac = ':'.join('%02x' % b for b in dest)
        source_mac = ':'.join('%02x' % b for b in src)
        eproto = socket.htons(prototype)
        self.matching_map["dest_mac"] = dest_mac
        self.matching_map["source_mac"] = source_mac
        self.matching_map["ether_proto"] = eproto
        if (eproto == socket.ntohs(0x0800)):
            self.parseIPHead(raw_data[14:])

    def parseIPv4Head(self,raw_data):
        self.packet += u"\u001b[42;1m[IPv4]\u001b[0m"
        iph = unpack('!BBHHHBBH4s4s',raw_data[:20])
        version_len = iph[0]
        version = version_len >> 4
        ihl = version_len & 0xF
        ihl_len =  ihl * 4
        self.matching_map["h_len"] = ihl_len
        ttl = iph[5]
        ipv4protocol = iph[6]
        source_addr = socket.inet_ntoa(iph[8])
        dest_addr = socket.inet_ntoa(iph[9])
        self.matching_map["ttl"] = ttl
        self.matching_map["ipv4protocol"] = ipv4protocol
        self.matching_map["v4source_addr"] = source_addr
        self.matching_map["v4dest_addr"] = dest_addr

        if (ipv4protocol == 1):
            self.parseICMPv4Head(raw_data[ihl_len:])

        elif (ipv4protocol == 6):
            self.parseTCPHead(raw_data[ihl_len:])
       
        elif(ipv4protocol == 17):
            self.parseUDPHead(raw_data[ihl_len:])

    def parseIPv6Head(self,raw_data):
        self.packet += u"\u001b[43;1m[IPv6]\u001b[0m"
        iph = struct.unpack('!HHHHHH16s16s',raw_data[:20])
        version_len = iph[0]
        version = version_len >> 4
        traffic_class = iph[5]
        flow_label = iph[6]
        header_len= iph[7]
        ipv6protocol = iph[8]
        v6source_addr = ':'.join('%0x{0:X2}' %b for b in iph[9])
        v6dest_addr = ':'.join('%0x{0:X2}' %b for b in iph[10])

        self.matching_map["traffic_class"] = traffic_class
        self.matching_map["flow_label"] = flow_label
        self.matching_map["header_len"] = header_len
        self.matching_map["ipv6protocol"] = ipv6protocol
        self.matching_map["v6source_addr"] = v6source_addr
        self.matching_map["v6dest_addr"] = v6dest_addr

        if (ipv6protocol == 1):
            self.parseICMPv6Head(raw_data[header_len:])
        elif (ipv6protocol == 6):
            self.parseTCPHead(raw_data[header_len:])
        elif(ipv6protocol == 17):
            self.parseUDPHead(raw_data[header_len:])

    def parseIPHead(self,raw_data):
        version_len = raw_data[0]
        version = version_len >> 4

        if (version == 4):
            self.parseIPv4Head(raw_data)
        else:
            self.parseIPv6Head(raw_data)

    def parseICMPv4Head(self,raw_data):
        self.packet +=u"\u001b[44;1mICMPv4\u001b[0m"
        typ,code,checksum,packetID,sequence = struct.unpack('!bbHHh',raw_data[:8])

        self.matching_map["icmp4type"] = typ
        self.matching_map["icmp4code"] = code

    def parseICMPv6Head(self,raw_data):
        self.packet += u"\u001b[44;1mICMPv6\u001b[0m"
        typ,code,checksum = struct.unpack('!bbH',raw_data[:4])

        self.matching_map["icmp6type"] = typ
        self.matching_map["icmp6code"] = code

    def parseTCPHead(self,raw_data):
        self.packet += u"\u001b[46m;1m[TCP]\u001b[0m"
        (tcpsrc_port,tcpdest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('!HHLLH',raw_data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1
        self.matching_map["tcpsrc_port"] = tcpsrc_port
        self.matching_map["tcpdest_port"] = tcpdest_port
        self.matching_map["flag_urg"] = flag_urg
        self.matching_map["flag_ack"] = flag_ack
        self.matching_map["flag_rst"] = flag_rst
        self.matching_map["flag_syn"] = flag_syn
        self.matching_map["flag_fin"] = flag_fin

    def parseUDPHead(self,raw_data):
        self.packet += u"\u001b[47;1m\u001b[30;1m[UDP]\u001b[0m\u001b[0m"
        pack = struct.unpack("!4H", raw_data[:8])
        self.matching_map["udpsrc_port"] = pack[0]
        self.matching_map["udpdest_port"] = pack[1]
        self.matching_map["udpdata_len"] = pack[2]

    def manageRules(self):
        print(u"**********************************************************************\n")
        print(u"*\u001b[44m\t\t\t\tADVANCE FIREWALL RULE MANAGEMENT\u001b[0m           *\n")            
        print(u"**********************************************************************\n")
        print(u"1.ADD RULE\n")
        print(u"2.UPDATE RULE\n")
        print(u"3.DELETE RULE\n")
        print(u"4.PRINT RULES\n")
        opt = int(input("Enter Your Option\n"))
        if (opt == 1):
            rule_struct = {}
            system("clear")
            print("Choose Type of Rule\n")
            print(u"1.Ethernet (Layer 2)\n")
            print(u"2.IP Rule (layer 3)\n")
            print(u"3.TCP Rule (layer 4)\n")
            print(u"4.UDP Rule (layer 4)\n")
            print(u"5.ICMP Rule (Layer 3)\n")
            rule_opt = int(input("Enter Your Option\n"))

            system("clear")

            if(rule_opt == 1):
                print(u"\u001b[33;1mEthernet Rule\n")
                print(u"\u001b[33;1mEnter the rule in analogical form: Field----Field----Rule(Allow/Discard)")
                rule_id = int(input("Enter Rule ID\n"))
                rule_struct["rule_id"] = rule_id
                if(input("Want to match Source MAC? (y/n)") == "y"):
                    src_mac = input("\u001b[33;1mEnter Source MAC : \u001b[0m")
                    rule_struct["source_mac"] = src_mac
                if (input("Want to match Destination MAC? (y/n)") == "y"):
                    dest_mac = input("\u001b[33;1mEnter Dest MAC : \u001b[0m")
                    rule_struct["dest_mac"] = dest_mac

                if (input("Want to match Protocol field? (y/n)") == "y"):
                    proto = input("\u001b[33;1mEnter protocol : \u001b[0m")
                    rule_struct["ether_proto"] = int(proto)

                rule = input("\u001b[33;1mEnter Rule (Allow/Discard)  : \u001b[0m")
                rule_struct["rule"] = rule

                self.all_rules["Ether_rules"].append(rule_struct)

                print(u"\u001b[42mRule Inserted\u001b[0m\n")
            elif (rule_opt == 2):
                if(int(input("Enter Type of IP Rule (4/6)") )== 4):
                    print(u"\u001b[33;1mIPv4 Rule\u001b[0m\n")
                    print(u"\u001b[33;1mEnter the rule in analogical form: Field----Field----Rule(Allow/Discard)\u001b[0m")

                    rule_id = int(input("Enter Rule ID\n"))
                    rule_struct["rule_id"] = rule_id
                    if (input("Want to match Source IP? (y/n)") == "y"):
                        src_ip = input("\u001b[33;1mEnter Source IP : \u001b[0m")
                        rule_struct["v4source_addr"] = src_ip
                    if (input("Want to match Dest IP? (y/n)") == "y"):
                        dest_ip = input("\u001b[33;1mEnter Dest IP : \u001b[0m")
                        rule_struct["v4dest_addr"] = dest_ip

                    if (input("Want to match Protocol Field? (y/n)") == "y"):
                        proto = input("\u001b[33;1mEnter IP Protocol Field : \u001b[0m")
                        rule_struct["ipv4protocol"] = int(proto)

                    if (input("Want to match Header_Len? (y/n)") == "y"):
                        h_len = input("\u001b[33;1mEnter Dest IP : \u001b[0m")
                        rule_struct["h_len"] = int(h_len)

                    if (input("Want to match TTL? (y/n)") == "y"):
                        ttl = input("\u001b[33;1mEnter TTL : \u001b[0m")
                        rule_struct["ttl"] = int(ttl)
                    if (input("Want to match TOS Field? (y/n)") == "y"):
                        tos = input("\u001b[33;1mEnter Dest IP : \u001b[0m")
                        rule_struct["tos"] = int(tos)

                    rule = input("Enter Rule (Allow/Discard : ")
                    rule_struct["rule"] = rule
                    self.all_rules["IPv4rules"].append(rule_struct)
                    print(u"\u001b[42mRule Inserted\u001b[0m\n")
                else:
                    print(u"\u001b[33;1mIPv6 Rule\u001b[0m\n")
                    print(u"\u001b[33;1mEnter the rule in analogical form: Field----Field----Rule(Allow/Discard)\u001b[0m")

                    rule_id = int(input("Enter Rule ID\n"))
                    rule_struct["rule_id"] = rule_id
                    if (input("Want to match Source IP? (y/n)") == "y"):
                        src_ip = input("\u001b[33;1mEnter Source IP : \u001b[0m")
                        rule_struct["v6source_addr"] = src_ip
                    if (input("Want to match Dest IP? (y/n)") == "y"):
                        dest_ip = input("\u001b[33;1mEnter Dest IP : \u001b[0m")
                        rule_struct["v6dest_addr"] = dest_ip

                    if (input("Want to match Protocol[Next Header] Field? (y/n)") == "y"):
                        proto = input("\u001b[33;1mEnter IP Protocol Field : \u001b[0m")
                        rule_struct["ipv6protocol"] = int(proto)

                    if (input("Want to match Header_Len? (y/n)") == "y"):
                        h_len = input("\u001b[33;1mEnter Dest IP : \u001b[0m")
                        rule_struct["header_len"] = int(h_len)

                    if (input("Want to match Traffic Class Field? (y/n)") == "y"):
                        tfclass = input("\u001b[33;1mEnter TTL : \u001b[0m")
                        rule_struct["traffic_class"] = tfclass

                    rule = input("Enter Rule (Allow/Discard : ")
                    rule_struct["rule"] = rule
                    self.all_rules["IPv6rules"].append(rule_struct)
                    print(u"\u001b[42mRule Inserted\u001b[0m\n")

            elif (rule_opt == 3):
                print(u"\u001b[33;1mTCP Rule\u001b[0m\n")
                print(u"\u001b[33;1mEnter the rule in analogical form: Field----Field----Rule(Allow/Discard)\u001b[0m")
                rule_id = int(input("Enter Rule ID\n"))
                rule_struct["rule_id"] = rule_id

                if(input("Want to match TCP Source Port? (y/n)") == "y"):
                    src_port = input("\u001b[33;1mEnter Source PORT: \u001b[0m")
                    rule_struct["tcpsrc_port"] = int(src_port)
                if(input("Want to match TCP Destination Port? (y/n)") == "y"):
                    dest_port = input("\u001b[33;1mEnter Destination PORT: \u001b[0m")
                    rule_struct["tcpdest_port"] = int(dest_port)

                if (input("Want to match TCP URG Flag Field? (y/n)") == "y"):
                    urg = input("\u001b[33;1mEnter URG Flag: \u001b[0m")
                    rule_struct["flag_urg"] = int(urg)

                if (input("Want to match TCP SYN Flag Field? (y/n)") == "y"):
                    syn = input("\u001b[33;1mEnter SYN Flag: \u001b[0m")
                    rule_struct["flag_syn"] = int(syn)

                if (input("Want to match TCP RST Flag Field? (y/n)") == "y"):
                    rst = input("\u001b[33;1mEnter RST Flag: \u001b[0m")
                    rule_struct["flag_rst"] = int(rst)

                rule = input("Enter Rule (Allow/Discard : ")
                rule_struct["rule"] = rule

                self.all_rules["TCPrules"].append(rule_struct)
                print(u"\u001b[42mRule Inserted\u001b[0m\n")

            elif(rule_opt == 4):
                print(u"\u001b[33;1mUDP Rule\u001b[0m\n")
                print(u"\u001b[33;1mEnter the rule in analogical form: Field----Field----Rule(Allow/Discard)")
                rule_id = int(input("Enter Rule ID\u001b[0m\n"))
                rule_struct["rule_id"] = rule_id

                if (input("Want to match UDP Source Port? (y/n)") == "y"):
                    src_port = input("\u001b[33;1mEnter Source PORT: \u001b[0m")
                    rule_struct["udpsrc_port"] = int(src_port)
                if (input("Want to match UDP Destination Port? (y/n)") == "y"):
                    dest_port = input("\u001b[33;1mEnter Destination PORT: \u001b[0m")
                    rule_struct["udpdest_port"] = int(dest_port)

                rule = input("Enter Rule (Allow/Discard : ")
                rule_struct["rule"] = rule
                self.all_rules["UDPrules"].append(rule_struct)
                print(u"\u001b[42mRule Inserted\u001b[0m\n")

            elif(rule_opt == 5):
                print(u"\u001b[33;1mICMP Rule\u001b[0m\n")
                print(u"\u001b[33;1mEnter the rule in analogical form: Field----Field----Rule(Allow/Discard)")
                rule_id = int(input("Enter Rule ID\u001b[0m\n"))
                rule_struct["rule_id"] = rule_id

                if(int(input("Enter ICMPv4 or ICMPv6 (4/6)\n")) == 4):
                    if(input("Want to match type field? (y/n)") == "y"):
                        typef = int(input("Enter Type : "))
                        rule_struct["icmp4type"] = typef

                    if(input("Want to match code field? (y/n)") == "y"):
                        code = int(input("Enter code : "))
                        rule_struct["icmp4code"] = code
                        
                else:
                    if(input("Want to match type field? (y/n)") == "y"):
                        typef = int(input("Enter Type : "))
                        rule_struct["icmp6type"] = typef

                    if(input("Want to match code field? (y/n)") == "y"):
                        code = int(input("Enter code : "))
                        rule_struct["icmp6code"] = code

                rule = input("Enter Rule (Allow/Discard : ")
                rule_struct["rule"] = rule

                self.all_rules["ICMPrules"].append(rule_struct)
                print(u"\u001b[42mRule Inserted\u001b[0m\n")
                
           

        elif(opt == 2):
            rule_type = input("Enter type of rule you wish to update[ipv4,ipv6,tcp,udp,ether,icmp]")
            if (rule_type == "ipv4"):
                id = int(input("Enter Rule ID to update"))
                updated = False
                for rule in self.all_rules["IPv4rules"]:
                    print("updatable items in rule :",rule.keys())
                    for key in rule.keys():
                        print("Enter updated value of ", key, "\n")
                        updated = input()
                        if (type(rule[key]) is int):
                            rule[key] = int(updated)
                        else:
                            rule[key] = updated
                    print(u"\u001b[42mRule Updated\n")
                    updated = True
                    break

            if (updated == False):
                print(u"\u001b[41mNo Such Rule Found\u001b[0m\n")

            elif (rule_type == "ipv6"):
                id = int(input("Enter Rule ID to update"))
                updated = False
                for rule in self.all_rules["IPv6rules"]:
                    print("updatable items in rule :",rule.keys())
                    for key in rule.keys():
                        print("Enter updated value of ", key, "\n")
                        updated = input()
                        if (type(rule[key]) is int):
                            rule[key] = int(updated)
                        else:
                            rule[key] = updated
                    print(u"\u001b[42mRule Updated\n")
                    updated = True
                    break
            if (updated == False):
                print(u"\u001b[41mNo Such Rule Found\u001b[0m\n")

            elif (rule_type == "tcp"):
                id = int(input("Enter Rule ID to update"))
                updated = False
                for rule in self.all_rules["TCPrules"]:
                    print("updatable items in rule :",rule.keys())
                    for key in rule.keys():
                        print("Enter updated value of ", key, "\n")
                        updated = input()
                        if (type(rule[key]) is int):
                            rule[key] = int(updated)
                        else:
                            rule[key] = updated
                    print(u"\u001b[42mRule Updated\n")
                    updated = True
                    break

            if (updated == False):
                print(u"\u001b[41mNo Such Rule Found\u001b[0m\n")

            elif (rule_type == "udp"):
                id = int(input("Enter Rule ID to update"))
                updated = False
                for rule in self.all_rules["UDPrules"]:
                    print("updatable items in rule :", rule.keys())
                    for key in rule.keys():
                        print("Enter updated value of ", key, "\n")
                        updated = input()
                        if (type(rule[key]) is int):
                            rule[key] = int(updated)
                        else:
                            rule[key] = updated
                    print(u"\u001b[42mRule Updated\n")
                    updated = True
                    break
            if (updated == False):
                print(u"\u001b[41mNo Such Rule Found\u001b[0m\n")

            elif (rule_type == "icmp"):
                id = int(input("Enter Rule ID to update"))
                updated = False
                for rule in self.all_rules["ICMPrules"]:
                    print("updatable items in rule :", rule.keys())
                    for key in rule.keys():
                        print("Enter updated value of ", key, "\n")
                        updated = input()
                        if (type(rule[key]) is int):
                            rule[key] = int(updated)
                        else:
                            rule[key] = updated
                    print(u"\u001b[42mRule Updated\n")
                    updated = True
                    break

            if (updated == False):
                print(u"\u001b[41mNo Such Rule Found\u001b[0m\n")

        elif(opt == 3):
            count = 0
            id = int(input("Enter Rule ID you wish to Delete\n"))

            for rulecat in self.all_rules.keys():
                deleted = False
                count = 0
                for rule in self.all_rules[rulecat]:
                    if (rule["rule_id"] == id):
                        deleted = True
                        break
                    else:
                        count = count + 1
                if (deleted == True):
                    del self.all_rules[rulecat][count]
                    print(u"\u001b[41mRule Deleted\u001b[0m\n")
                    break
            if(deleted == False):
                print(u"\u001b[41mNo Such Rule Found\u001b[0m\n")


        elif(opt == 4):
            print(u"\u001b[46mExisting Rules In System\u001b[0m")
            for rulecat in self.all_rules.keys():
                print("**************************\n")
                print(rulecat,"\n")
                print("**************************\n")
                for rule in self.all_rules[rulecat]:
                    print(rule,"\n")

    def decideRule(self,raw_data):                                         #Core Function that makes packet decisions based on rules and also DoS attacks if turned on
        self.parseEtherHead(raw_data) 
        allowed = False

        if(self.matching_map["v4source_addr"] in self.dos_track and self.dos_switch == True):
            self.dos_track[self.matching_map["v4source_addr"]] = self.dos_track[self.matching_map["v4source_addr"]] + 1

        else:
             self.dos_track[self.matching_map["v4source_addr"]] = 0
             
        for rulecat in self.all_rules.keys():
            for rule in self.all_rules[rulecat]:
                for key in rule.keys():
                    if (key != "rule_id" and key != "rule"):
                        if (rule[key] == self.matching_map[key]):
                            match = True
                        else:
                            match = False
                if (match == True):
                    if (rule["rule"].lower() == "allow"):
                        allowed = True
                    else:
                        allowed = False
        if(self.dos_track[self.matching_map["v4source_addr"]]> self.dos_threshold):      #Checking DOS threshold, if the IP crosses dos threshold, probable DoS attack , hence discard packet
            
            print(" \u001b[41;1m DoS Detected\u001b[0m\n")
            allowed = False
            
        return allowed

    def startFirewall(self):
        print("\u001b[41;1m\t\tAdvanced Firewall Running...\u001b[0m \u001b[412;1m(Press any key to interrupt for opening rule manager)\u001b[0m\n")
        try:
            ptype = ""
            timer = time.time()
            while True:
                all_socks = [self.host1sock, self.extsock]
        
                if(time.time() - timer >= 1):
                    self.allowed_pack.append(self.allowed)
                    self.discarded_pack.append(self.discarded)
                    timer = time.time()

                ready_socks, _, _ = select.select(all_socks, [], [])
                for soc in ready_socks:
                    raw_data, addr = soc.recvfrom(65565)
                    start = time.process_time()
                    ret = self.decideRule(raw_data)
                    proc_time = time.process_time() - start
                    self.times.append(proc_time)
                    self.avg_time = sum(self.times)/len(self.times) 

                    if (ret == True):
                        self.allowed = self.allowed + 1
                        if (self.matching_map["v4dest_addr"] == "10.0.0.2"):
                            ptype = "\u001b[411;1mInbound\u001b[0m"
                            self.host1sock.sendall(raw_data)
                        else:
                            ptype = "\u001b[411;1mOutbound\u001b[0m"
                            self.extsock.sendall(raw_data)

                        print(u"Packet \u001b[42;1m Allowed  \u001b[0m\t Packet Type: ", ptype, "\tPacket Shape : ", self.packet,"Process Time : ",proc_time,"seconds","\n")
                    else:
                        self.discarded = self.discarded + 1
                        if (self.matching_map["v4dest_addr"] == "10.0.0.2"):
                            ptype = "\u001b[411;1mInbound\u001b[0m"
                        else:
                            ptype = "\u001b[411;1mOutbound\u001b[0m"

                        print(u"Packet \u001b[41;1m Discarded\u001b[0m\t Packet Type: ", ptype,"\tPacket Shape : ",self.packet,"Process Time : ",proc_time,"Seconds","\n")
        except KeyboardInterrupt as e:
            print("Interrupted For Rule Management\n")
            system("clear")
            self.manageRules()
            input(u"\u001b[31;1mPress Enter to continue\u001b[0m\n")

    def getStatistics(self):                                                           #This method prints and plots various performance related metrics of the firewall system
        time = 1
        print("**********************************************\n")
        print(u"\u001b[44;1m\t\tSTATISTICS\u001b[0m\n")
        print("*********************************************\n")
        print("The Statistics of the system are as follows\n")
        print("Average Time Taken to process packet : ",self.avg_time,"\n")
        print("No of packets allowed : ",self.allowed,"\n")
        print("No of packets dropped : ",self.discarded,"\n")
        print("No of rules in system : ",len(self.all_rules["Ether_rules"])+len(self.all_rules["IPv4rules"])+len(self.all_rules["IPv6rules"])+len(self.all_rules["TCPrules"])+len(self.all_rules["UDPrules"]))
        max_match = 0

        for rulecat in self.all_rules.keys():
            for rule in self.all_rules[rulecat]:
                if (max_match < len(rule.keys()) - 2):
                    max_match = len(rule.keys()) - 2
        print("Maximum Matching Fields in Rules : ",max_match,"\n")
        '''
        print("Packets Allowed/Discarded w.r.t time\n")
        print("No of Packets Allowed\t\t\t\tTime (Seconds)\n")
        for i in range(len(self.allowed_pack)):
            print(self.allowed_pack[i],"\t\t\t\t",time,"\n")
            time = time + 1
        time = 1
        print("\nNo of Packets Discarded\t\t\t\tTime(Seconds)\n")
        for i in range(len(self.discarded_pack)):
            print(self.discarded_pack[i],"\t\t\t\t",time,"\n")
            time = time + 1
        '''
        allowed_packets = list(int(i) for i in set(self.allowed_pack))
        discarded_packets = list(int(i) for i in set(self.discarded_pack))
        allow_times = []
        for i in range(len(allowed_packets)):
            allow_times.append(i)

        discard_times = []
        for i in range(len(discarded_packets)):
            discard_times.append(i)

        plt.plot(np.array(allow_times),np.array(allowed_packets))
        plt.plot(np.array(discard_times),np.array(discarded_packets))
        plt.xlabel("Time (Seconds)")
        plt.ylabel("No of Allowed/Discarded packet)")
        plt.title("Packets Processing")
        plt.legend(['Allowed','Discarded'])
        plt.savefig("allow_dis.png")

    def saveRules(self):
        with open('rule_base.txt','w') as outfile:
            json.dump(self.all_rules,outfile)

    def loadRules(self):
        with open('rule_base.txt','r') as infile:
            self.all_rules = json.load(infile)

    def set_dos_threshold(self):
        sta = input("Want to Turn on DoS detection? (y/n)")          # Only when the DoS Detection is desired it can be turned on
        if(sta == "y"):
            self.dos_switch = True
            thresh = int(input("Enter new threshold limit : \n"))
            self.dos_threshold = thresh
        else:
            self.dos_switch = False

if __name__ == "__main__":
    firewall_opt = sys.argv[1]
    interface1 = sys.argv[2]
    interface2 = sys.argv[3]

    while True:
        if firewall_opt == "simple_firewall":
            banner = pyfiglet.figlet_format("SIMPLE FIREWALL","standard")
            print(banner)
            #print(u"\u001b[33;1m\t\t\tSIMPLE FIREWALL\u001b[0m\n")
            print(u"\u001b[33;1m1.Start Firewall\u001b[0m\n")
            print(u"\u001b[33;1m2.Print Firewall description\u001b[0m\n")
            print(u"\u001b[33;1m3.Exit\u001b[0m\n")
            option = int(input("Enter Your Choice:\n"))
            if (option == 1):
                sf = SimpleFirewall(interface1,interface2)
                sf.startFirewall()

            elif (option == 2):
                system("clear")
                print(u"\u001b[36;1m\t\t\tSimple Firewall\u001b[0m\n")
                print(u"\u001b[36;1mSimple Firewall represents a simple hardcoded rule based firewall, which works on conditional check on the predefinde hardcoded rule in the program to filter the packets. This Firewall works for only IPV4 packets.\u001b[0m\n")
            elif (option == 3):
                exit(0)
            else:
                print("Error : Wrong Option\n")

        elif firewall_opt == "adv_firewall":
            af = AdvancedFirewall(interface1,interface2)
            while True:
                system("clear")
               # print(u"*********************************************************\n")
               #print(u"*\u001b[33;1m\t\t\tADVANCED FIREWALL\u001b[0m              *\n")
                banner = pyfiglet.figlet_format("ADVANCED FIREWALL","standard")
                print(banner)
               # print(u"*********************************************************\n")
                print(u"\u001b[33;1m1.Start Firewall\u001b[0m\n")
                print(u"\u001b[33;1m2.Print Firewall description\u001b[0m\n")
                print(u"\u001b[33;1m3.Manage Rules\u001b[0m\n")
                print(u"\u001b[33;1m4.Statistics\u001b[0m\n")
                print(u"\u001b[33;1m5.Save Rules\u001b[0m\n")
                print(u"\u001b[33;1m6.Load Rules\u001b[0m\n")
                print(u"\u001b[33;1m7 DoS Threshold\u001b[0m\n")
                print(u"\u001b[33;1m8.Exit\u001b[0m\n")
                option = int(input("Enter Your Choice:\n"))

                system("clear")
                if (option == 1):

                    af.startFirewall()

                elif (option == 2):
                    banner = pyfiglet.figlet_format("ADVANCED FIREWALL","standard")
                    print(banner)
                    print( u"\u001b[36;1mAdvanced Firewall represents the complex and full scale dynamic firewall system, which provides rule management, statistics report, etc. It supports from layer 2 to layer 4.\u001b[0m\n")
                    input(u"\u001b[31;1mPress Enter to continue\u001b[0m\n")
                elif (option == 3):
                    af.manageRules()
                    input(u"\u001b[31;1mPress Enter to continue\u001b[0m\n")

                elif (option == 4):
                    af.getStatistics()
                    input(u"\u001b[31;1mPress Enter to continue\u001b[0m\n")

                elif(option == 5):
                    af.saveRules()
                    input(u"\u001b[31;1mRules Saved\u001b[0m\n")
                    input(u"\u001b[31;1mPress Enter to continue\u001b[0m\n")

                elif(option == 6):
                    af.loadRules()
                    input(u"\u001b[31;1mRules Loaded\u001b[0m\n")
                    input(u"\u001b[31;1mPress Enter to continue\u001b[0m\n")

                elif(option == 7):
                    af.set_dos_threshold()
                    input(u"\u001b[31;1mThreshold Updated..Press Enter\u001b[0m\n")

                elif(option == 8):
                    exit(0)




