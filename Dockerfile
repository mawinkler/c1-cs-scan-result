FROM python:3.8-slim

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY requirements.txt /usr/src/app
RUN pip3 install --no-cache-dir -r requirements.txt

COPY scan-result.py /usr/src/app
COPY config.yml /usr/src/app

ENTRYPOINT [ "python", "./scan-result.py"]
