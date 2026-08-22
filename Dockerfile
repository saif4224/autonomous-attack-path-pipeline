FROM python:3.11-slim

# nmap is the only external binary the pipeline shells out to;
# Nessus and Metasploit are reached over the network via their APIs.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/output

ENTRYPOINT ["python", "-m", "pentest_pipeline.cli"]
CMD ["--demo"]
