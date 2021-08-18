# We use this script to test all others.
import arp_spofer.arp_spof as AS
import network_discovery.network_scanner as NS

ArpSpoofing = NS.ArpSpoofing()
ArpSpoofing.scan()
