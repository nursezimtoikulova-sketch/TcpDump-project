from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


def print_banner():
    console.print(Panel.fit(
        "[bold cyan]TCP Traffic Analyzer[/bold cyan]\n"
        "[white]Real-time Network Packet Sniffer[/white]\n"
        "[dim]Built with Python + Scapy | WSL Ubuntu[/dim]",
        border_style="cyan"
    ))


def print_packet(info: dict, verbose: bool = False):
    proto  = info.get("protocol", "OTHER")
    src    = info.get("src", "?")
    dst    = info.get("dst", "?")
    ts     = info.get("timestamp", "")
    length = info.get("length", 0)
    detail = info.get("info", "")

    color = {
        "TCP":   "green",
        "UDP":   "yellow",
        "ICMP":  "red",
        "DNS":   "magenta",
        "NTP":   "blue",
        "HTTPS": "cyan",
        "SSH":   "bright_red",
        "HTTP":  "bright_green",
        "ARP":   "bright_blue",
    }.get(proto, "white")

    console.print(
        f"[dim]{ts}[/dim]  "
        f"[bold {color}]{proto:<6}[/bold {color}]  "
        f"[white]{src:<25}[/white] → "
        f"[white]{dst:<25}[/white]  "
        f"[dim]len={length:<5}[/dim]  "
        f"[italic dim]{detail}[/italic dim]"
    )

    if verbose and info.get("details"):
        console.print(f"         [dim]↳ {info['details']}[/dim]")


def print_stats(stats: dict):
    console.print()
    table = Table(
        title="📊 Capture Statistics",
        box=box.ROUNDED,
        border_style="cyan",
        title_style="bold cyan"
    )

    table.add_column("Protocol", style="bold yellow",   width=12)
    table.add_column("Packets",  style="bold green",    justify="right", width=10)
    table.add_column("Bytes",    style="bold blue",     justify="right", width=12)
    table.add_column("Percent",  style="bold magenta",  justify="right", width=10)

    total_p = stats.get("total_packets", 1)
    total_b = stats.get("total_bytes", 0)

    for proto, data in sorted(
        stats.get("protocols", {}).items(),
        key=lambda x: x[1]["count"],
        reverse=True
    ):
        pct = (data["count"] / total_p) * 100
        table.add_row(
            proto,
            str(data["count"]),
            f"{data['bytes']:,}",
            f"{pct:.1f}%"
        )

    table.add_section()
    table.add_row(
        "[bold]TOTAL[/bold]",
        f"[bold]{total_p}[/bold]",
        f"[bold]{total_b:,}[/bold]",
        "[bold]100%[/bold]"
    )

    console.print(table)
