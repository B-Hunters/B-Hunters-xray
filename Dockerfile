FROM python:3.10-slim
RUN apt update
RUN apt install libpcap0.8-dev libuv1-dev -y && apt clean && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir b-hunters==1.1.7
# WORKDIR /app/service
# COPY dirsearchm /app/service/dirsearchm
# CMD [ "python", "-m", "dirsearchm" ]
COPY ./xray/ /xray/
WORKDIR  /app/
COPY ./xray/xray.yaml /
COPY ./xray/module.xray.yaml /
COPY ./xray/config.yaml /
COPY ./xray/plugin.xray.yaml /
WORKDIR /app/service
COPY xraym /app/service/xraym
CMD [ "python", "-m", "xraym" ]

# ENTRYPOINT [ "/bin/bash" ]