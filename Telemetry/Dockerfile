FROM debian:stable-slim     
RUN apt-get update
RUN apt-get install -y python3.10 python3-pip
RUN pip3 install --upgrade pip
RUN mkdir /Telemtry
WORKDIR /Telemetry
COPY . /Telemetry
RUN pip install -r requirements.txt
RUN chmod a+x run.sh
CMD ["./run.sh"]
