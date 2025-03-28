FROM python:3.10-slim

WORKDIR /app
COPY . /app

RUN apt update && apt install -y curl
# Install libpcap and other dependencies
RUN apt update && apt install -y libpcap-dev tcpdump curl

RUN pip install --no-cache-dir -r requirements.txt

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]