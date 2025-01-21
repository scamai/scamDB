FROM ubuntu:22.04

WORKDIR /app


COPY requirements.txt /app/

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


RUN pip3 install --no-cache-dir -r requirements.txt

COPY . /app

EXPOSE 8001


CMD [ "fastapi", "run" ,"main.py" ]
