import scapy.all as scapy

from ProtocolParser import (
    IPv4Parser,
    EthernetParser,
    TCP_Parser,
    UDP_Parser,
    ICMP_Parser,
)


def SniffedPackets(pkt):
    if pkt.haslayer(scapy.Ether):
        # EthernetParser(pkt=pkt[scapy.Ether])
        if pkt.haslayer(scapy.IP):

            # IPv4Parser(pkt=pkt[scapy.IP])

            if pkt.haslayer(scapy.TCP):
                # TCP_Parser(pkt=pkt[scapy.TCP])
                pass
            elif pkt.haslayer(scapy.UDP):
                # UDP_Parser(pkt=pkt[scapy.UDP])
                pass
            elif pkt.haslayer(scapy.ICMP):
                icmp_data = pkt.getlayer(scapy.ICMP)
                ICMP_Parser(pkt=pkt)
            # elif pkt.haslayer(scapy.IGMP):
            #     igmp_data = pkt.getLayer(scapy.getlayer(scapy.IGMP))
            else:
                print("Unknown Layer 4 Protocol:")
                print(pkt.layers)

                print("=" * 30)

    elif pkt.haslayer(scapy.Dot3):
        # print("Dot3 is not supported")
        pass
    else:
        print(list(pkt))
    # if pkt.haslayer(http.HTTPRequest):
    #     print("A packet from %s to %s" % (pkt[scapy.IP].src, pkt[scapy.IP].dst))
    #     # print(pkt.show())
    #     print(pkt[http.HTTPRequest].Host + pkt[http.HTTPRequest].Path)
    #     if pkt.haslayer(scapy.Raw):
    #         # print(pkt[scapy.Raw])
    #         pass


def Sniff():
    scapy.sniff(iface="wlx048d386d5289", store=False, prn=SniffedPackets)


Sniff()
