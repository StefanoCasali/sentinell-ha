ARG BUILD_FROM
FROM $BUILD_FROM

# nmap: scoperta ARP con MAC e produttore. iproute2: rete e gateway dell'host.
RUN apk add --no-cache python3 nmap iproute2 iputils

COPY app /app
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# with-contenv restituisce al processo l'ambiente del container (SUPERVISOR_TOKEN), che s6 altrimenti azzera.
CMD ["sh", "-c", "if [ -x /command/with-contenv ]; then exec /command/with-contenv python3 -m sentinella; else exec python3 -m sentinella; fi"]
