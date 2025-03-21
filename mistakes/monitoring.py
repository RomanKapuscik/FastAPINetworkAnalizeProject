import platform
from difflib import SequenceMatcher

import psutil
from scapy.all import get_if_list, get_if_addr


def similar(a, b):
    """
    Funkcja do porównywania podobieństwa między ciągami.
    """
    return SequenceMatcher(None, a, b).ratio()


def get_network_interfaces():
    """
    Tworzy mapowanie {czytelny interfejs: systemowa wersja Scapy}.
    """
    system = platform.system()
    readable_to_system = {}
    scapy_interfaces = get_if_list()  # Pobranie interfejsów Scapy

    # Ręczne mapowanie dla problematycznych interfejsów
    manual_map = {
        "Realtek RTL8852BE WiFi 6 802.11ax PCIe Adapter": "\\Device\\NPF_{40B83518-F6C4-4722-B34D-EE59818B7A34}",
        "VirtualBox Host-Only Ethernet Adapter": "\\Device\\NPF_{121BC957-3F85-4036-9D66-57139EF375E3}",
        "TP-Link Wireless USB Adapter": "\\Device\\NPF_{74BA469D-948B-48E7-830C-9CFF2F27F0D2}"
    }

    if system == "Windows":
        import pythoncom
        import wmi
        pythoncom.CoInitialize()  # Inicjalizacja modelu COM dla WMI
        try:
            c = wmi.WMI()
            for interface in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                name = interface.Description  # Czytelna nazwa interfejsu
                ip_addresses = interface.IPAddress  # Adresy IP
                ip_display = f" (IP: {', '.join(ip_addresses)})" if ip_addresses else " (No IP)"

                # Najpierw sprawdź w ręcznym mapowaniu
                if name in manual_map:
                    readable_to_system[f"{name}{ip_display}"] = manual_map[name]
                    continue

                # Elastyczne dopasowanie do nazw Scapy
                best_match = None
                best_score = 0
                for scapy_iface in scapy_interfaces:
                    score = similar(name, scapy_iface)
                    if score > best_score:
                        best_score = score
                        best_match = scapy_iface

                if best_match and best_score > 0.6:  # Próg podobieństwa 60%
                    readable_to_system[f"{name}{ip_display}"] = best_match
                else:
                    readable_to_system[f"{name}{ip_display}"] = None
                    print(
                        f"Could not match psutil interface '{name}' with any Scapy interface. Best score: {best_score}")
        finally:
            pythoncom.CoUninitialize()  # Zakończenie COM

    elif system in ["Linux", "Darwin"]:  # Obsługa dla Linux/macOS
        interfaces = psutil.net_if_addrs()
        for name, addrs in interfaces.items():
            ip_addresses = [addr.address for addr in addrs if addr.family == psutil.AF_INET]
            ip_display = f" (IP: {', '.join(ip_addresses)})" if ip_addresses else " (No IP)"

            # Dopasowanie nazw między psutil a Scapy
            best_match = None
            best_score = 0
            for scapy_iface in scapy_interfaces:
                score = similar(name, scapy_iface)
                if score > best_score:
                    best_score = score
                    best_match = scapy_iface

            if best_match and best_score > 0.6:  # Próg podobieństwa 60%
                readable_to_system[f"{name}{ip_display}"] = best_match
            else:
                readable_to_system[f"{name}{ip_display}"] = None
                print(f"Could not match psutil interface '{name}' with any Scapy interface. Best score: {best_score}")

    else:  # Fallback dla innych systemów operacyjnych
        for interface in scapy_interfaces:
            ip_address = get_if_addr(interface) if interface else "No IP"
            readable_to_system[f"{interface} (IP: {ip_address})"] = interface

    return readable_to_system


# Testowanie
if __name__ == "__main__":
    # interfaces = get_network_interfaces()
    # from pprint import pprint
    #
    # pprint(interfaces)  # Wyświetlenie mapowania
    #
    # available_interfaces = get_if_list()
    # print("Available interfaces in Scapy:")
    # for iface in available_interfaces:
    #     print(iface)

    from scapy.all import sniff


    def print_packet(packet):
        if packet.haslayer("IP"):
            print(packet.summary())


    sniff(iface="\\Device\\NPF_{74BA469D-948B-48E7-830C-9CFF2F27F0D2}", prn=print_packet, count=5, timeout=10)
    # sniff(iface="\\Device\\NPF_{0C893E25-03A1-4F23-B113-8853881E9AD8}", prn=print_packet, count=5, timeout=10)

    # '\\Device\\NPF_{74BA469D-948B-48E7-830C-9CFF2F27F0D2}'
