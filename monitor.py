from scapy.all import sniff
from main import app


@app.get("/monitor/")
def monitor_traffic(interface: str = "eth0", count: int = 10):
    # Przechwytywanie pakietów na wybranym interfejsie
    packets = sniff(count=count, iface=interface)
    captured = []

    # Analiza przechwyconych pakietów
    for pkt in packets:
        if pkt.haslayer("IP"):
            captured.append({
                "src": pkt["IP"].src,
                "dst": pkt["IP"].dst,
                "proto": pkt["IP"].proto
            })

    return {"captured_packets": captured}
