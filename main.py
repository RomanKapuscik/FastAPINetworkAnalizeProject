# from io import BytesIO
#
# import matplotlib.pyplot as plt
# from fastapi import FastAPI, File, UploadFile, HTTPException, Depends
# from fastapi.responses import JSONResponse
# from fastapi.responses import StreamingResponse
# from scapy.all import sniff
# from sqlalchemy.orm import Session
#
# from continuous_monitor import start_monitoring, stop_monitoring_service
# from database import Packet, get_db
# from utils import process_pcap, validate_pcap
#
# app = FastAPI()
#
#
# @app.get("/")
# def read_root():
#     return {"message": "Witaj w analizatorze ruchu sieciowego!"}
#
# # @app.get(
# #     "/monitor/",
# #     summary="Monitor network traffic",
# #     description="This endpoint captures network packets in real-time on a specified interface. "
# #                 "You can specify the number of packets to capture and analyze their details."
# # )
# # def monitor_traffic(interface: str = "eth0", count: int = 10, db: Session = Depends(get_db)):
# #     try:
# #         packets = sniff(count=count, iface=interface)
# #         for pkt in packets:
# #             if pkt.haslayer("IP"):
# #                 new_packet = Packet(
# #                     src_ip=pkt["IP"].src,
# #                     dst_ip=pkt["IP"].dst,
# #                     protocol=str(pkt["IP"].proto)
# #                 )
# #                 db.add(new_packet)
# #         db.commit()
# #     except Exception as e:
# #         raise HTTPException(status_code=400, detail=f"Error capturing packets: {str(e)}")
# #
# #     return {"message": f"Captured and saved {count} packets to the database"}
#
#
# @app.exception_handler(Exception)
# async def global_exception_handler(request, exc):
#     return JSONResponse(
#         status_code=500,
#         content={"message": "An unexpected error occurred. Please try again later."}
#     )
#
#
# @app.post("/start-monitoring/")
# def api_start_monitoring(interface: str = "eth0", db: Session = Depends(get_db)):
#     return start_monitoring(interface, db)
#
#
# @app.post("/stop-monitoring/")
# def api_stop_monitoring():
#     return stop_monitoring_service()
#
#
# @app.get("/network-traffic/")
# def get_traffic(limit: int = 100, db: Session = Depends(get_db)):
#     packets = db.query(Packet).order_by(Packet.timestamp.desc()).limit(limit).all()
#     return [
#         {"timestamp": pkt.timestamp, "src_ip": pkt.src_ip, "dst_ip": pkt.dst_ip, "protocol": pkt.protocol}
#         for pkt in packets
#     ]


from fastapi import FastAPI, Depends
from threading import Thread
from database import get_db, DATABASE_URL, Base, engine
from sqlalchemy.orm import Session
import time
from sqlalchemy import create_engine, MetaData

from monitor_traffic import monitor_traffic

metadata = MetaData()

# Funkcja sprawdzająca dostępność bazy danych
def wait_for_db():
    while True:
        try:
            with engine.connect():
                print("Database is ready!")
                break
        except Exception as e:
            print("Waiting for the database to be ready...")
            time.sleep(5)
app = FastAPI()

@app.on_event("startup")
async def startup():
    Base.metadata.create_all(bind=engine)

@app.post("/start-monitoring/")
def start_monitoring(interface: str = "eth0", db: Session = Depends(get_db)):
    """
    Starts monitoring network traffic on the specified interface.
    """
    monitor_thread = Thread(target=monitor_traffic, args=(interface, db))
    monitor_thread.daemon = True
    monitor_thread.start()
    return {"message": f"Monitoring started on interface {interface}"}