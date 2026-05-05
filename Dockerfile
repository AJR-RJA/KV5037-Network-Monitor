# initializing dockerfile
FROM python:3.12-slim

# working directory for dockerfile commands
WORKDIR /app

# update and install libpcap-dev (required by Scapy for raw packet capture)
RUN apt-get update && apt-get install -y libpcap-dev && rm -rf /var/lib/apt/lists/*

# install python dependencies
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# copy app and whitelist database
COPY app.py app.py
COPY data.sqlite data.sqlite

# expose metrics port (flask uses network_mode: host so this is informational only)
EXPOSE 8000

# run the app
CMD ["python", "app.py"]
