import signal
import sys
from scapy.all import sniff, wrpcap
from parser import parse_packet
from filters import PacketFilter
from display import print_packet, print_stats, console


class PacketCapture:
    def __init__(
        self,
        interface: str          = None,
        count:     int          = 0,
        verbose:   bool         = False,
        save_file: str          = None,
        pfilter:   PacketFilter = None,
    ):
        self.interface = interface
        self.count     = count
        self.verbose   = verbose
        self.save_file = save_file
        self.pfilter   = pfilter or PacketFilter()
        self.packets   = []
        self.stats     = {
            "total_packets": 0,
            "total_bytes":   0,
            "protocols":     {}
        }
        signal.signal(signal.SIGINT, self._stop)

    def _handle_packet(self, packet):
        if not self.pfilter.match(packet):
            return

        info = parse_packet(packet)
        self.packets.append(packet)

        proto = info["protocol"]
        self.stats["total_packets"] += 1
        self.stats["total_bytes"]   += info["length"]

        if proto not in self.stats["protocols"]:
            self.stats["protocols"][proto] = {"count": 0, "bytes": 0}

        self.stats["protocols"][proto]["count"] += 1
        self.stats["protocols"][proto]["bytes"] += info["length"]

        print_packet(info, self.verbose)

    def start(self):
        console.print(
            f"\n[bold green]✅ Capture Started[/bold green]\n"
            f"  Interface : [cyan]{self.interface or 'auto'}[/cyan]\n"
            f"  Count     : [cyan]{self.count or 'unlimited'}[/cyan]\n"
            f"  Save to   : [cyan]{self.save_file or 'none'}[/cyan]\n"
        )
        console.print("[dim]Press Ctrl+C to stop...[/dim]\n")

        try:
            sniff(
                iface=self.interface,
                prn=self._handle_packet,
                count=self.count if self.count > 0 else 0,
                store=False,
            )
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

        self._finish()

    def _finish(self):
        if self.save_file and self.packets:
            wrpcap(self.save_file, self.packets)
            console.print(
                f"\n[green]💾 Saved {len(self.packets)} "
                f"packets → {self.save_file}[/green]"
            )
        print_stats(self.stats)

    def _stop(self, sig, frame):
        console.print("\n[yellow]⏹  Stopping capture...[/yellow]")
        self._finish()
        sys.exit(0)
