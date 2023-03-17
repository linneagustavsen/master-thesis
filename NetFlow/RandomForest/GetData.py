import pandas as pd
from datetime import datetime,timedelta
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from silk import *
from .IsAttackFlow import *

def getData(silkFile, start, stop):
    infile = silkfile_open(silkFile, READ)
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
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
    label=[]


    for rec in infile:
        if rec.etime >= stopTime:
            break
        if rec.stime < startTime:
            continue
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
        label.append(int(isAttackFlow(rec.sip, rec.dip)))

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
     "label": label
    })
    return data

def getEntropyData(silkFile, start, stop, frequency, interval):
    #Makes a datetime object of the input start time
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    windowTime = startTime
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    records = []
    
    ipSrcArray = []
    ipSrcRateArray = []

    ipDstArray = []
    ipDstRateArray = []

    flowArray = []
    flowRateArray = []

    numberOfFlows = []

    icmpRatioArray = []
    icmpPacketsArray = []
    timeArray = []
    #Instantiate counter variable
    i = 0
    sizes = []
    lastMinuteSize = 0

    #Loop through all the flow records in the input file
    for rec in infile:
        if rec.etime >= stopTime:
            break
        if rec.stime < startTime:
            continue
            
        #Aggregate flows into the specified time interval
        if rec.stime >= startTime + interval:
            #Find the probability distribution based on how many packets there is in each source flow in this time interval
            PiSIP, ns = ipSourceDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropySip = generalizedEntropy(10,PiSIP)
            ipSrcArray.append(entropySip)
            #Calculate the generalized entropy rate of this distribution
            ipSrcRateArray.append(entropySip/ns)

            #Find the probability distribution based on how many packets there is in each destination flow in this time interval
            PiDIP, nd = ipDestinationDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropyDip = generalizedEntropy(10,PiDIP)
            ipDstArray.append(entropyDip)
            #Calculate the generalized entropy rate of this distribution
            ipDstRateArray.append(entropyDip/nd)
            
            #Find the probability distribution based on how many packets there is in each bi-directional flow in this time interval
            PiF, nf = flowDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropyFlow = generalizedEntropy(10, PiF)
            flowArray.append(entropyFlow)
            #Calculate the generalized entropy rate of this distribution
            flowRateArray.append(entropyFlow/nf)

            #Store the number of bi-directional flows in this time interval
            numberOfFlows.append(nf)

            #Find the ratio of ICMP packets in this time interval
            icmpRatio, icmpPackets = icmpDistribution(records)
            icmpRatioArray.append(icmpRatio)
            icmpPacketsArray.append(icmpPackets)
            timeArray.append(startTime.strftime("%Y-%m-%d %H:%M"))
            #Reset the record aggregation
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            i += 1

        if rec.stime >= windowTime + frequency:
            thisMinuteSize = len(records) - lastMinuteSize
            sizes.append(thisMinuteSize)
            lastMinuteSize = thisMinuteSize
            windowTime += frequency
        records.append(rec)
        
    entropy = pd.DataFrame(
    {"time": timeArray,
     "entropy_ip_source": ipSrcArray,
     "entropy_rate_ip_source": ipSrcRateArray,
     "entropy_ip_destination": ipDstArray,
     "entropy_rate_ip_destination": ipDstRateArray,
     "entropy_flow": flowArray,
     "entropy_rate_flow": flowRateArray,
     "number_of_flows": numberOfFlows,
     "icmp_ratio": icmpRatioArray,
     "number_of_icmp_packets": icmpPacketsArray
    })

    return entropy