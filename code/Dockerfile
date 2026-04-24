FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y libpcap-dev && rm -rf /var/lib/apt/lists/*
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py app.py
COPY data.sqlite data.sqlite
EXPOSE 5000
CMD ["python", "app.py"]
