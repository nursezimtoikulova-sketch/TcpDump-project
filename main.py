import click
from display import print_banner, console
from capture import PacketCapture
from filters import PacketFilter


@click.command()
@click.option("-i", "--interface", default=None,
              help="Network interface (eth0, lo ...)")
@click.option("-c", "--count", default=0,
              help="Number of packets (0 = unlimited)")
@click.option("-p", "--protocol", default=None,
              type=click.Choice(
                  ["TCP", "UDP", "ICMP", "ARP"],
                  case_sensitive=False
              ),
              help="Filter by protocol")
@click.option("--src", default=None, help="Filter by source IP")
@click.option("--dst", default=None, help="Filter by destination IP")
@click.option("--port", default=None, type=int, help="Filter by port")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.option("-w", "--write", default=None, help="Save to .pcap file")
@click.option("--list-interfaces", is_flag=True,
              help="Show available interfaces")
def main(interface, count, protocol, src, dst,
         port, verbose, write, list_interfaces):
    """
    \b
    TCP Traffic Analyzer — Real-time CLI Packet Sniffer
    =====================================================
    Examples:
      sudo venv/bin/python main.py
      sudo venv/bin/python main.py -c 50
      sudo venv/bin/python main.py -p TCP
      sudo venv/bin/python main.py -p UDP
      sudo venv/bin/python main.py -p ICMP -v
      sudo venv/bin/python main.py --port 53 -v
      sudo venv/bin/python main.py --port 123
      sudo venv/bin/python main.py -w capture.pcap
      sudo venv/bin/python main.py --list-interfaces
    """
    print_banner()

    if list_interfaces:
        from scapy.all import get_if_list
        console.print("\n[bold]Available Interfaces:[/bold]")
        for iface in get_if_list():
            console.print(f"  [cyan]• {iface}[/cyan]")
        return

    pfilter = PacketFilter(
        protocol=protocol,
        src_ip=src,
        dst_ip=dst,
        port=port,
    )

    capture = PacketCapture(
        interface=interface,
        count=count,
        verbose=verbose,
        save_file=write,
        pfilter=pfilter,
    )
    capture.start()


if __name__ == "__main__":
    main()
