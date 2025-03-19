
from fastapi import FastAPI, File, UploadFile, HTTPException, Depends
from scapy.all import sniff
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from continuous_monitor import start_monitoring, stop_monitoring_service
from utils import process_pcap, validate_pcap
from io import BytesIO
import matplotlib.pyplot as plt
from fastapi.responses import StreamingResponse
from database import Packet, get_db



app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Witaj w analizatorze ruchu sieciowego!"}

@app.post(
    "/analyze/",
    summary="Analyze a .pcap file",
    description="This endpoint allows you to upload a .pcap file and analyzes its content. It extracts source IP,"
                "destination IP, and protocol information."
        )
async def analyze_pcap(file: UploadFile = File(...)):
    try:
        content = await file.read()
        validated_content = validate_pcap(file)
        packets, protocol_counts = process_pcap(validated_content)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    analysis = [{"src": pkt["IP"].src, "dst": pkt["IP"].dst, "proto": pkt["IP"].proto}
                for pkt in packets if pkt.haslayer("IP")]

    return {"packet_count": len(analysis), "details": analysis, "protocol_distribution": protocol_counts}


@app.post("/analyze/visualize/")
async def visualize_pcap(file: UploadFile = File(...)):
    try:
        content = await file.read()
        validated_content = validate_pcap(file)
        _, protocol_counts = process_pcap(validated_content)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Tworzenie wykresu
    fig, ax = plt.subplots()
    ax.bar(protocol_counts.keys(), protocol_counts.values(), color=['blue', 'orange', 'green', 'red'])
    ax.set_title("Packet Protocol Distribution")
    ax.set_xlabel("Protocol")
    ax.set_ylabel("Count")

    buffer = BytesIO()
    plt.savefig(buffer, format="png")
    buffer.seek(0)
    plt.close(fig)

    return StreamingResponse(buffer, media_type="image/png")


@app.get(
         "/monitor/",
         summary="Monitor network traffic",
         description="This endpoint captures network packets in real-time on a specified interface. "
                     "You can specify the number of packets to capture and analyze their details."
         )
def monitor_traffic(interface: str = "eth0", count: int = 10, db: Session = Depends(get_db)):
    try:
        packets = sniff(count=count, iface=interface)
        for pkt in packets:
            if pkt.haslayer("IP"):
                new_packet = Packet(
                    src_ip=pkt["IP"].src,
                    dst_ip=pkt["IP"].dst,
                    protocol=str(pkt["IP"].proto)
                )
                db.add(new_packet)
        db.commit()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error capturing packets: {str(e)}")

    return {"message": f"Captured and saved {count} packets to the database"}



@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={"message": "An unexpected error occurred. Please try again later."}
    )

@app.post("/start-monitoring/")
def api_start_monitoring(interface: str = "eth0", db: Session = Depends(get_db)):
    return start_monitoring(interface, db)

@app.post("/stop-monitoring/")
def api_stop_monitoring():
    return stop_monitoring_service()

@app.get("/network-traffic/")
def get_traffic(limit: int = 100, db: Session = Depends(get_db)):
    packets = db.query(Packet).order_by(Packet.timestamp.desc()).limit(limit).all()
    return [
        {"timestamp": pkt.timestamp, "src_ip": pkt.src_ip, "dst_ip": pkt.dst_ip, "protocol": pkt.protocol}
        for pkt in packets
    ]
