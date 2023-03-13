import pandas as pd
def getDataTraining(infile):
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
    
    data= pd.DataFrame(
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
    return data

def getDataTesting(infile):
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
    sTime=[]
    duration=[]
    eTime=[]
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
        sTime.append(rec.stime)
        duration.append(rec.duration_secs)
        eTime.append(rec.etime)
        nhIP.append(int(rec.nhip))

    data= pd.DataFrame(
    {"sTime": sTime,
     "eTime": eTime,
     "srcIP": sIP,
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
    return data