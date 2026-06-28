from scapy.all import IP, TCP, UDP, ICMP, ARP


class PacketFilter:
    def __init__(
        self,
        protocol: str = None,
        src_ip:   str = None,
        dst_ip:   str = None,
        port:     int = None,
    ):
        self.protocol = protocol.upper() if protocol else None
        self.src_ip   = src_ip
        self.dst_ip   = dst_ip
        self.port     = port

    def match(self, packet) -> bool:

        # Filter by protocol
        if self.protocol:
            if self.protocol == "TCP"  and TCP  not in packet: return False
            if self.protocol == "UDP"  and UDP  not in packet: return False
            if self.protocol == "ICMP" and ICMP not in packet: return False
            if self.protocol == "ARP"  and ARP  not in packet: return False

        # Filter by IP
        if IP in packet:
            if self.src_ip and packet[IP].src != self.src_ip:
                return False
            if self.dst_ip and packet[IP].dst != self.dst_ip:
                return False

        # Filter by port
        if self.port:
            matched = False
            if TCP in packet:
                if (packet[TCP].sport == self.port or
                        packet[TCP].dport == self.port):
                    matched = True
            if UDP in packet:
                if (packet[UDP].sport == self.port or
                        packet[UDP].dport == self.port):
                    matched = True
            if not matched:
                return False

        return True
