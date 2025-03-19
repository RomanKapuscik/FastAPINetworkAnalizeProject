from fastapi import FastAPI, File, UploadFile, HTTPException
from scapy.all import sniff
from scapy.all import rdpcap
from fastapi.responses import JSONResponse

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
    if not file.filename.endswith(".pcap"):
        raise HTTPException(status_code=400, detail="Uploaded file must be a .pcap file")

    content = await file.read()
    temp_filename = "temp.pcap"

    with open(temp_filename, "wb") as f:
        f.write(content)

    try:
        packets = rdpcap(temp_filename)
        if len(packets) == 0:
            raise ValueError("No packets found in the .pcap file")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid .pcap file: {str(e)}")

    analysis = [{"src": pkt["IP"].src, "dst": pkt["IP"].dst, "proto": pkt["IP"].proto}
                for pkt in packets if pkt.haslayer("IP")]

    return {"packet_count": len(analysis), "details": analysis}

@app.get(
         "/monitor/",
         summary="Monitor network traffic",
         description="This endpoint captures network packets in real-time on a specified interface. "
                     "You can specify the number of packets to capture and analyze their details."
         )
def monitor_traffic(interface: str = "eth0", count: int = 10):
    if count <= 0:
        raise HTTPException(status_code=400, detail="Count must be a positive integer")

    try:
        packets = sniff(count=count, iface=interface)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error capturing packets: {str(e)}")

    captured = [{"src": pkt["IP"].src, "dst": pkt["IP"].dst, "proto": pkt["IP"].proto}
                for pkt in packets if pkt.haslayer("IP")]

    return {"captured_packets": captured}


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={"message": "An unexpected error occurred. Please try again later."}
    )