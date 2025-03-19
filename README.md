# FastAPI Network Analyzer

This project is a **network analyzer and visualization tool** built with FastAPI. It allows users to analyze `.pcap` files and monitor network traffic in real time. The application also provides easy-to-use APIs and a visualization of network data for better understanding.

---

## Features

1. **Analyze `.pcap` files**:
   - Extracts data from `.pcap` files (such as source and destination IPs, and protocols).
   - Returns details about packets and their protocol distribution in JSON format.

2. **Visualize network data**:
   - Generates a chart that shows the distribution of network protocols (e.g., TCP, UDP, ICMP).

3. **Real-time network monitoring** (optional):
   - Monitors live network traffic and analyzes captured packets (future expansion).

4. **API Documentation**:
   - Provides built-in interactive documentation via Swagger UI.

---

## Getting Started

### Prerequisites

- **Python 3.10** or higher
- **Docker** and **Docker Compose**

### Installation (with Docker)

1. Clone this repository:
   ```bash
   git clone https://github.com/RomanKapuscik/FastAPINetworkAnalizeProject.git
   cd NetworkAnalyzer