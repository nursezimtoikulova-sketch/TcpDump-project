from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS
from datetime import datetime


def parse_packet(packet) -> dict:
    result = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "src":       "?",
        "dst":       "?",
        "protocol":  "OTHER",
        "length":    len(packet),
        "info":      "",
        "details":   "",
    }

    # ARP
    if ARP in packet:
        result["protocol"] = "ARP"
        result["src"]      = packet[ARP].psrc
        result["dst"]      = packet[ARP].pdst
        result["info"]     = f"Who has {packet[ARP].pdst}?"
        return result

    if IP not in packet:
        return result

    result["src"] = packet[IP].src
    result["dst"] = packet[IP].dst

    # ICMP
    if ICMP in packet:
        result["protocol"] = "ICMP"
        types = {0: "Echo Reply", 8: "Echo Request", 3: "Unreachable"}
        t = packet[ICMP].type
        result["info"]    = types.get(t, f"Type={t}")
        result["details"] = f"TTL={packet[IP].ttl}"
        return result

    # TCP
    if TCP in packet:
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        proto = _get_tcp_proto(sport, dport)
        flags = _get_flags(packet[TCP].flags)

        result["protocol"] = proto
        result["src"]      = f"{packet[IP].src}:{sport}"
        result["dst"]      = f"{packet[IP].dst}:{dport}"
        result["info"]     = f"Flags=[{flags}]"
        result["details"]  = (
            f"Seq={packet[TCP].seq} "
            f"Win={packet[TCP].window} "
            f"TTL={packet[IP].ttl}"
        )
        return result

    # UDP
    if UDP in packet:
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        proto = _get_udp_proto(sport, dport)

        result["protocol"] = proto
        result["src"]      = f"{packet[IP].src}:{sport}"
        result["dst"]      = f"{packet[IP].dst}:{dport}"

        if DNS in packet:
            dns = packet[DNS]
            if dns.qr == 0 and dns.qdcount > 0:
                try:
                    name = dns.qd.qname.decode()
                    result["info"] = f"Query: {name}"
                except Exception:
                    result["info"] = "DNS Query"
            else:
                result["info"] = f"Response: {dns.ancount} answers"
        else:
            result["info"] = f"Len={packet[UDP].len}"

        return result

    return result


def _get_flags(flags) -> str:
    flag_map = {
        "S": "SYN",
        "A": "ACK",
        "F": "FIN",
        "R": "RST",
        "P": "PSH",
        "U": "URG"
    }
    return " ".join(
        v for k, v in flag_map.items() if k in str(flags)
    ) or str(flags)


def _get_tcp_proto(sport, dport) -> str:
    ports = {
        80:   "HTTP",
        443:  "HTTPS",
        22:   "SSH",
        21:   "FTP",
        25:   "SMTP",
        53:   "DNS",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
    }
    return ports.get(dport) or ports.get(sport) or "TCP"


def _get_udp_proto(sport, dport) -> str:
    ports = {
        53:   "DNS",
        67:   "DHCP",
        68:   "DHCP",
        123:  "NTP",
        161:  "SNMP",
        5353: "mDNS",
    }
    return ports.get(dport) or ports.get(sport) or "UDP"
