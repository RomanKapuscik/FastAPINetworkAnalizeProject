from datetime import datetime
from sqlalchemy.orm import Session
from database import get_db, CapturedPacket
from scapy.all import sniff

def monitor_traffic(interface: str, db_session: Session):
    """
    Monitors network traffic on a specified interface and saves data to MariaDB.
    """
    def process_packet(packet):
        try:
            # Wyciąganie danych z pakietu
            src_ip = packet["IP"].src if packet.haslayer("IP") else None
            dst_ip = packet["IP"].dst if packet.haslayer("IP") else None
            protocol = packet.name if packet.name else None
            timestamp = datetime.now()

            # Tworzenie nowego wpisu
            new_packet = CapturedPacket(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                timestamp=timestamp
            )
            db_session.add(new_packet)
            db_session.commit()

        except Exception as e:
            print(f"Error processing packet: {e}")

    sniff(iface=interface, prn=process_packet, filter="ip", store=0)