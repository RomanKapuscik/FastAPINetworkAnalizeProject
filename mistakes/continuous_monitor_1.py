import threading

from scapy.all import sniff

from database import Packet

monitor_thread = None
stop_monitoring = threading.Event()


def monitor_network_continuously(interface: str, db_session):
    def process_packet(packet):
        if packet.haslayer("IP"):
            new_packet = Packet(
                src_ip=packet["IP"].src,
                dst_ip=packet["IP"].dst,
                protocol=str(packet["IP"].proto)
            )
            db_session.add(new_packet)
            db_session.commit()

    sniff(iface=interface, prn=process_packet, store=False, stop_filter=lambda x: stop_monitoring.is_set())


def start_monitoring(interface: str, db_session):
    global monitor_thread, stop_monitoring

    if monitor_thread and monitor_thread.is_alive():
        return {"message": "Monitoring is already running"}

    stop_monitoring.clear()
    monitor_thread = threading.Thread(target=monitor_network_continuously, args=(interface, db_session))
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
