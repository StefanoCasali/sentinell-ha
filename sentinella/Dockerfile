ARG BUILD_FROM
FROM $BUILD_FROM

# nmap: scoperta ARP con MAC e produttore. iproute2: rete e gateway dell'host.
RUN apk add --no-cache python3 nmap iproute2 iputils

COPY app /app
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

CMD ["python3", "-m", "sentinella"]
