#initializing dockerfile
FROM python:3.12-slim

#working directory for dockerfile commands
WORKDIR /app

#update and make sure recent version of libpcap-dev is installed
RUN apt-get update && apt-get install -y libpcap-dev && rm -rf /var/lib/apt/lists/*

#install recent version of any programs in the requirements.txt
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

#runs back-end and MAC address database
COPY app.py app.py
COPY data.sqlite data.sqlite

#ports used in docker
EXPOSE 8000, 9090, 3000, 9093

#execute python and back-end
CMD ["python", "app.py"]
