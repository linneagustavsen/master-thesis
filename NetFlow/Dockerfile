FROM ubuntu:18.04
        
RUN apt-get update
RUN apt-get install -y python3.10 python3-pip
RUN pip3 install --upgrade pip

RUN mkdir /NetFlow
WORKDIR /NetFlow
COPY . /NetFlow
RUN chmod a+x run.sh
CMD ["./run.sh"]
