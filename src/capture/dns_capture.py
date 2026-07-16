from datetime import datetime

from scapy.all import DNS, DNSQR, IP, sniff


class DNSCapture:

    def __init__(self, packet_handler):
        self.packet_handler = packet_handler

    def process_packet(self, packet):

        if not packet.haslayer(DNS):
            return

        if not packet.haslayer(DNSQR):
            return

        if not packet.haslayer(IP):
            return

        dns_layer = packet[DNS]

        # Only process DNS queries.
        if dns_layer.qr != 0:
            return

        query = packet[DNSQR]

        try:
            domain = query.qname.decode(
                "utf-8",
                errors="ignore"
            ).rstrip(".")
        except AttributeError:
            return

        dns_event = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": packet[IP].src,
            "destination_ip": packet[IP].dst,
            "domain": domain.lower(),
            "query_type": query.qtype,
            "packet_size": len(packet),
            "transaction_id": dns_layer.id,
        }

        self.packet_handler(dns_event)

    def start(self, interface=None):

        print("[+] DNS packet capture started")
        print("[+] Waiting for DNS queries...")
        print()

        sniff(
            iface=interface,
            filter="port 53",
            prn=self.process_packet,
            store=False
        )
