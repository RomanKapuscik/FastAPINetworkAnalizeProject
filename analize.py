from fastapi import File, UploadFile
from scapy.all import rdpcap
from main import app


@app.post("/analyze/")
async def analyze_pcap(file: UploadFile = File(...)):
    # Odczytanie pliku od użytkownika
    content = await file.read()
    temp_filename = "temp.pcap"

    # Zapisanie pliku tymczasowego
    with open(temp_filename, "wb") as f:
        f.write(content)

    # Wczytanie pakietów z pliku .pcap za pomocą Scapy
    packets = rdpcap(temp_filename)
    analysis = []

    # Analiza pakietów
    for pkt in packets:
        if pkt.haslayer("IP"):
            analysis.append({
                "src": pkt["IP"].src,
                "dst": pkt["IP"].dst,
                "proto": pkt["IP"].proto
            })

    return {"packet_count": len(analysis), "details": analysis}
