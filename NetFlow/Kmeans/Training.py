from sklearn.cluster import KMeans
import numpy as np
from datetime import datetime
from silk import *
import pandas as pd
import pickle

def training(silkFile, start, stop):
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    infile = silkfile_open(silkFile, READ)
    sIP=[]
    dIP=[]
    sPort=[]
    dPort=[]
    protocol=[]
    packets=[]
    flowBytes=[]
    fin=[]
    syn=[]
    rst=[]
    psh=[]
    ack=[]
    urg=[]
    ece=[]
    cwr=[]
    duration=[]
    nhIP=[]


    for rec in infile:
        sIP.append(int(rec.sip))
        dIP.append(int(rec.dip))
        sPort.append(rec.sport)
        dPort.append(rec.dport)
        protocol.append(rec.protocol)
        packets.append(rec.packets)
        flowBytes.append(rec.bytes)
        fin.append(int(rec.tcpflags.fin))
        syn.append(int(rec.tcpflags.syn))
        rst.append(int(rec.tcpflags.rst))
        psh.append(int(rec.tcpflags.psh))
        ack.append(int(rec.tcpflags.ack))
        urg.append(int(rec.tcpflags.urg))
        ece.append(int(rec.tcpflags.ece))
        cwr.append(int(rec.tcpflags.cwr))
        duration.append(rec.duration_secs)
        nhIP.append(int(rec.nhip))

    trainingData = pd.DataFrame(
    {"srcIP": sIP,
     "dstIP": dIP,
     "srcPort": sPort,
     "dstPort": dPort,
     "protocol": protocol,
     "packets": packets,
     "bytes": flowBytes,
     "fin": fin,
     "syn": syn,
     "rst": rst,
     "psh": psh,
     "ack": ack,
     "urg": urg,
     "ece": ece,
     "cwr": cwr,
     "duration": duration,
     "nestHopIP": nhIP,
    })

    trainingData.to_pickle("NetFlow/Kmeans/RawData/RawTrainingData")
    print(trainingData.head)
    kmeans = KMeans(n_clusters=2, random_state=0, n_init="auto").fit(trainingData)
    pickle.dump(kmeans, open("NetFlow/Kmeans/Models/MLmodel.pkl", 'wb'))

silkFile="/home/linneafg/silk-data/RawDataFromFilter/two-hours-2011-01-01_10-11-sorted.rw"
start = "2011-01-10 00:00:00"
stop = "2011-01-11 00:00:00"
 
training(silkFile, start, stop)