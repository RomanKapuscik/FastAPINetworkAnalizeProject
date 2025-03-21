import streamlit as st
import requests
import pandas as pd
import plotly.express as px

API_URL = "http://localhost:8000"

st.title("Network Traffic Monitor & Analyzer")

st.header("Network Monitoring")

interfaces_response = requests.get(f"{API_URL}/interfaces/")
if interfaces_response.status_code == 200:
    interfaces = interfaces_response.json()
else:
    interfaces = ["eth0", "lo"]

interface = st.selectbox("Select Network Interface", interfaces)

col1, col2 = st.columns(2)

with col1:
    if st.button("Start Monitoring"):
        response = requests.post(f"{API_URL}/start-monitoring/", data={"interface": interface})
        if response.status_code == 200:
            st.success(response.json()["message"])
        else:
            st.error(f"Error: {response.json().get('detail', 'Unknown error')}")

with col2:
    if st.button("Stop Monitoring"):
        response = requests.post(f"{API_URL}/stop-monitoring/")
        if response.status_code == 200:
            st.success(response.json()["message"])
        else:
            st.error(f"Error: {response.json().get('detail', 'Unknown error')}")

st.subheader("Recent Network Traffic")
limit = st.slider("Number of records to display", 10, 100, 50)

response = requests.get(f"{API_URL}/network-traffic/?limit={limit}")
if response.status_code == 200:
    data = response.json()
    if data:
        df = pd.DataFrame(data)
        st.dataframe(df)
    else:
        st.warning("No data available yet.")
else:
    st.error(f"Failed to fetch data: {response.json().get('detail', 'Unknown error')}")

st.header("Traffic Visualization")

response = requests.get(f"{API_URL}/network-traffic/?limit=100")
if response.status_code == 200:
    data = response.json()
    if data:

        df = pd.DataFrame(data)
        df["timestamp"] = pd.to_datetime(df["timestamp"])

        chart_type = st.selectbox("Select Chart Type", ["Packets Over Time", "Protocol Distribution"])

        if chart_type == "Packets Over Time":
            grouped = df.groupby(df["timestamp"].dt.minute).size().reset_index(name="count")
            grouped.rename(columns={"timestamp": "time"}, inplace=True)

            fig = px.line(grouped, x="time", y="count", title="Network Traffic Over Time")
            st.plotly_chart(fig)

        elif chart_type == "Protocol Distribution":
            protocol_counts = df["protocol"].value_counts().reset_index()
            protocol_counts.columns = ["protocol", "count"]

            fig = px.pie(protocol_counts, names="protocol", values="count", title="Protocol Distribution")
            st.plotly_chart(fig)

    else:
        st.warning("No data available yet for visualization.")
else:
    st.error(f"Failed to fetch data: {response.json().get('detail', 'Unknown error')}")