# FastAPI Network Monitor & Analyzer

This project is a **network traffic monitoring and analysis tool** built with FastAPI. It allows users to analyze
`.pcap` files, monitor network traffic in real-time, and save the results to a lightweight SQLite database. The
application also provides a visualization feature to help users better understand network traffic patterns.

---

## Features

1. **Continuous Network Monitoring**:
    - Monitors live network traffic on a specified interface.
    - Continuously saves traffic data (source IP, destination IP, protocol) to a SQLite database.

2. **Analyze `.pcap` Files**:
    - Extracts information from `.pcap` files, including packet source, destination, and protocol type.
    - Provides details in JSON format for deeper insights.

3. **Visualization**:
    - Generates visual charts to display packet distribution by protocol from `.pcap` files.

4. **Retrieve Traffic History**:
    - Query recent network traffic data from the SQLite database.
    - Helps track historical network activity for analysis.

5. **Interactive API Documentation**:
    - Built-in Swagger UI for easy exploration of the API.

---

## Getting Started

### Prerequisites

- **Python 3.10** or higher
- **Docker** and **Docker Compose**

---

## Installation (Docker Compose)

1. Clone this repository:
   ```bash
   git clone https://github.com/RomanKapuscik/FastAPINetworkAnalizeProject.git
   cd NetworkAnalyzer

2. Build and run the application using Docker Compose:
   ````bash
   docker-compose up --build

3. Access the application at:
    - Visit http://localhost:8000/docs for interactive Swagger documentation.
    - Open your browser and go to http://localhost:8000 for the API.

4. Perform Network Traffic Monitoring:
    - Start monitoring on a specific network interface (e.g., eth0)
      ```bash
      curl -X POST "http://localhost:8000/start-monitoring/" -d "interface=eth0"
    - Fetch recent network traffic data:
    ````bash
   curl -X GET "http://localhost:8000/network-traffic/?limit=50"

5. Analyze .pcap files:
    - Upload a .pcap file for analysis:
   ````bash
   curl -X POST "http://localhost:8000/analyze/" -F "file=@yourfile.pcap"

- Generate a protocol distribution chart:
     ````bash
     curl -X POST "http://localhost:8000/analyze/visualize/" -F "file=@yourfile.pcap" --output chart.png

6. Check the Database:
   Use tools like DB Browser for SQLite or instect the file network_data.db to view stored data.

7. Jak uruchomić GUI
   Uruchom interfejs Streamlit zaktualizowanym plikiem:
   ````bash
   streamlit run app.py