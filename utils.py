from fastapi import HTTPException
from scapy.all import rdpcap

def process_pcap(file_content: bytes):
    temp_filename = "temp.pcap"
    with open(temp_filename, "wb") as f:
        f.write(file_content)

    try:
        packets = rdpcap(temp_filename)
        if len(packets) == 0:
            raise ValueError("No packets found in the .pcap file")
    except Exception as e:
        raise ValueError(f"Error processing .pcap file: {str(e)}")

    protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
    for pkt in packets:
        if pkt.haslayer("TCP"):
            protocol_counts["TCP"] += 1
        elif pkt.haslayer("UDP"):
            protocol_counts["UDP"] += 1
        elif pkt.haslayer("ICMP"):
            protocol_counts["ICMP"] += 1
        else:
            protocol_counts["Other"] += 1

    return packets, protocol_counts

def validate_pcap(file):
    if not file.filename.endswith(".pcap"):
        raise HTTPException(status_code=400, detail="Uploaded file must be a .pcap file")
    content = file.read()
    return content
