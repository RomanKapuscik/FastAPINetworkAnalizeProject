
import platform
import psutil
from scapy.all import get_if_list, get_if_addr


def get_network_interfaces():
    system = platform.system()
    readable_interfaces = []

    if system == "Windows":
        import pythoncom
        import wmi
        pythoncom.CoInitialize()
        try:
            c = wmi.WMI()
            for interface in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                name = interface.Description
                ip_addresses = interface.IPAddress
                ip_display = f" (IP: {', '.join(ip_addresses)})" if ip_addresses else " (No IP)"
                readable_interfaces.append(f"{name}{ip_display}")
        finally:
            pythoncom.CoUninitialize()

    elif system in ["Linux", "Darwin"]:
        interfaces = psutil.net_if_addrs()
        for name, addrs in interfaces.items():
            ip_addresses = [addr.address for addr in addrs if addr.family == psutil.AF_INET]
            ip_display = f" (IP: {', '.join(ip_addresses)})" if ip_addresses else " (No IP)"
            readable_interfaces.append(f"{name}{ip_display}")

    else:
        interfaces = get_if_list()
        for interface in interfaces:
            ip_address = get_if_addr(interface) if interface else "No IP"
            readable_interfaces.append(f"{interface} (IP: {ip_address})")

    return readable_interfaces

# Testing
if __name__ == "__main__":
    # interfaces = get_network_interfaces()
    # print("Available interfaces:")
    # for iface in interfaces:
    #     print(iface)

    import os
    import time

    try:
        while True:
            os.system("curl https://8.8.8.8")
            time.sleep(1)
    except KeyboardInterrupt:
        print("sending packets done")
