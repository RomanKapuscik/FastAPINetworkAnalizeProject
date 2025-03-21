import pandas as pd
import plotly.express as px
import requests
import streamlit as st

from mistakes.monitoring import get_network_interfaces  # Import funkcji mapującej

API_URL = "http://localhost:8000"  # URL backendu

st.title("Network Traffic Monitor & Analyzer")

# Pobierz mapowanie interfejsów
interface_map = get_network_interfaces()  # {czytelny interfejs: systemowa nazwa Scapy}
readable_interfaces = list(interface_map.keys())  # Klucze (czytelne nazwy interfejsów)

# Wyświetl listę rozwijaną
selected_readable = st.selectbox("Select Network Interface", options=readable_interfaces)

# Sekcja: Rozpoczęcie monitorowania
if st.button("Start Monitoring"):
    # Pobierz systemową nazwę wybranego interfejsu
    selected_system = interface_map.get(selected_readable)
    if selected_system:
        response = requests.post(f"{API_URL}/start-monitoring/", data={"interface": selected_system})
        if response.status_code == 200:
            st.success(f"Monitoring started on: {selected_readable}")
        else:
            st.error(f"Error: {response.json().get('detail', 'Unknown error')}")
    else:
        st.error("Could not map selected interface to system name.")

# Sekcja: Zatrzymanie monitorowania
if st.button("Stop Monitoring"):
    response = requests.post(f"{API_URL}/stop-monitoring/")
    if response.status_code == 200:
        st.success("Monitoring stopped.")
    else:
        st.error(f"Error: {response.json().get('detail', 'Unknown error')}")

# Sekcja: Tabela z ostatnim ruchem sieciowym
st.subheader("Recent Network Traffic")
traffic_response = requests.get(f"{API_URL}/network-traffic/")
if traffic_response.status_code == 200:
    packets = traffic_response.json()  # Odbierz pakiety jako listę
    if packets:
        # Tworzenie tabeli z danych o pakietach
        df = pd.DataFrame(packets)
        st.dataframe(df)  # Wyświetlanie danych w formie tabeli
    else:
        st.info("No recent traffic recorded.")
else:
    st.error("Failed to fetch network traffic data.")

# Sekcja: Wizualizacja danych w formie wykresu
st.subheader("Traffic Visualization")
if traffic_response.status_code == 200 and packets:
    # Agregacja danych dla wizualizacji
    protocol_counts = df['protocol'].value_counts().reset_index()
    protocol_counts.columns = ['Protocol', 'Count']

    # Rysowanie wykresu
    fig = px.bar(protocol_counts, x='Protocol', y='Count', title='Packet Protocol Distribution')
    st.plotly_chart(fig)  # Wyświetlanie wykresu
else:
    st.info("No data available for visualization.")

# Opcjonalne odświeżanie interfejsów
if st.button("Refresh Interfaces"):
    interface_map = get_network_interfaces()
    readable_interfaces = list(interface_map.keys())
    st.experimental_rerun()
