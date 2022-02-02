import scapy.all as scapy
from scapy.all import Packet
from scapy.layers import http


def IPv4Parser(pkt: Packet) -> None:
    print("An IPv4 packet")
    print("From: %s" % pkt.src, "To: %s" % pkt.dst)


def EthernetParser(pkt: Packet) -> None:
    """

    :param pkt: a layer 2 object
    :return:
    """
    print("Frame src: %s" % pkt.src, 'To: %s")' % pkt.dst)


def TCP_Parser(pkt: Packet) -> None:
    print("Destination Port: %s" % pkt.dport)


def UDP_Parser(pkt: Packet) -> None:
    print("Destination Port: %s" % pkt.dport)


def IGMP_Parser(pkt: Packet) -> None:
    pass


def ICMP_Parser(pkt: Packet) -> None:
    # print(pkt.show())
    print(
        "ICMP Packet from: %s" % pkt.getlayer(scapy.IP).src,
        "To: %s" % pkt.getlayer(scapy.IP).dst,
    )
    print("ICMP Type %s" % pkt.getlayer(scapy.ICMP).type)
    print("ICMP Type %s" % pkt.getlayer(scapy.ICMP).type)


def HTTPRequest_Parser(pkt: Packet) -> None:
    pass


def HTTPResponse_Parser(pkt: Packet) -> None:
    pass


def ARP_Parser(pkt: Packet) -> None:
    pass
