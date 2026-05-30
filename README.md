# Network Forensics & Traffic Analysis Lab

## Objective

This project aimed to build a controlled environment for capturing, 
inspecting, and analyzing network traffic using Wireshark and TCPDump.  
The primary focus was to examine PCAP files, identify suspicious 
communication patterns, investigate protocol behavior, and document 
findings in structured security reports.  

This hands-on lab was designed to strengthen practical skills in 
network forensics, packet analysis, and threat identification — 
core competencies for a SOC Analyst role.

---

### Skills Learned

- Practical understanding of packet capture and network forensics methodology.
- Ability to filter, inspect, and interpret raw network traffic using Wireshark.
- Proficiency in identifying suspicious patterns such as port scans, 
  unusual DNS queries, and unauthorized connection attempts.
- Understanding of key network protocols: TCP/IP, DNS, HTTP, ICMP, ARP.
- Development of structured security reporting and documentation skills.
- Critical thinking and investigative mindset applied to real network data.

---

### Tools Used

- **Wireshark** — for deep packet inspection and protocol analysis.
- **TCPDump** — for command-line packet capture and filtering.
- **PCAP files** — pre-captured network traffic samples used for analysis.
- **Linux CLI** — for running TCPDump commands and managing capture files.

---

## Steps

### Step 1 — Setting Up the Environment
Configured the analysis environment on Linux.  
Installed Wireshark and verified TCPDump was available via CLI.  
Downloaded sample PCAP files for analysis.

*Ref 1: Wireshark interface showing loaded PCAP file*  
![screenshot](your-screenshot-link-here)

---

### Step 2 — Capturing Live Traffic with TCPDump
Used TCPDump to capture live packets on the network interface.  
Applied filters to isolate specific traffic types (DNS, HTTP, ICMP).

```bash
sudo tcpdump -i eth0 -w capture.pcap
sudo tcpdump -i eth0 port 53
