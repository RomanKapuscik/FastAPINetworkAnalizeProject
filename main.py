from fastapi import FastAPI, File, UploadFile

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Witaj w analizatorze ruchu sieciowego!"}

# @app.post("/analyze/")
# async def analyze_pcap(file: UploadFile = File(...)):
#     # Tutaj zaimplementujemy analizę pliku .pcap za pomocą Scapy.
#     return {"filename": file.filename, "status": "Analysis in progress"}

@app.post("/simulate/")
def simulate_traffic(ip: str, packet_type: str):
    # Tutaj dodamy funkcjonalność generowania ruchu sieciowego za pomocą Scapy.
    return {"ip": ip, "packet_type": packet_type, "status": "Simulation in progress"}

# @app.get("/monitor/")
# def monitor_traffic():
#     # Tu dodamy funkcję monitorowania ruchu w czasie rzeczywistym.
#     return {"status": "Monitoring started"}