import threading

from scapy.all import sniff

from database import Packet

monitor_thread = None
stop_monitoring = threading.Event()


def monitor_network_continuously(interface: str, db_session):
    def process_packet(packet):
        try:
            src_ip = packet["IP"].src if packet.haslayer("IP") else None
            dst_ip = packet["IP"].dst if packet.haslayer("IP") else None
            src_mac = packet.src if packet.src else None
            dst_mac = packet.dst if packet.dst else None
            length = len(packet)
            src_port = packet.sport if packet.haslayer("TCP") or packet.haslayer("UDP") else None
            dst_port = packet.dport if packet.haslayer("TCP") or packet.haslayer("UDP") else None
            protocol = packet.name if packet.name else None

            new_packet = Packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_mac=src_mac,
                dst_mac=dst_mac,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                length=length,
            )
            db_session.add(new_packet)
            db_session.commit()
        except Exception as e:
            print(f"Error processing packet: {e}")

    sniff(
        iface=interface,
        prn=process_packet,
        store=False,
        stop_filter=lambda x: stop_monitoring.is_set()
    )


def start_monitoring(interface: str, db_session):
    global monitor_thread, stop_monitoring

    if monitor_thread and monitor_thread.is_alive():
        return {"message": "Monitoring is already running"}

    stop_monitoring.clear()
    monitor_thread = threading.Thread(
        target=monitor_network_continuously,
        args=(interface, db_session)
    )
    monitor_thread.daemon = True
    monitor_thread.start()

    return {"message": f"Started monitoring network traffic on interface {interface}"}


def stop_monitoring_service():
    global stop_monitoring, monitor_thread

    if monitor_thread and monitor_thread.is_alive():
        stop_monitoring.set()
        monitor_thread.join()
        return {"message": "Monitoring has been stopped"}
    else:
        return {"message": "No active monitoring process to stop"}
