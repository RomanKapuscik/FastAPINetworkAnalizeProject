import threading
from scapy.all import sniff
from database import get_db, Packet
from sqlalchemy.orm import Session

# Funkcja do monitorowania sieci w tle
def monitor_network_continuously(interface: str, db: Session):
    def process_packet(packet):
        if packet.haslayer("IP"):
            new_packet = Packet(
                src_ip=packet["IP"].src,
                dst_ip=packet["IP"].dst,
                protocol=str(packet["IP"].proto)
            )
            db.add(new_packet)
            db.commit()

    # Monitorowanie pakietów w nieskończonej pętli
    sniff(iface=interface, prn=process_packet, store=False)

