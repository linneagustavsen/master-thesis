from .Distributions import *
from .GeneralizedEntropy import *
import pandas as pd
from datetime import datetime
from silk import *
from .IsAttack import *

'''
    Get data from an raw SiLK file of NetFlow records
    Input:  
            silkFile:   string, path to the raw SiLK file sorted on time
            start:      datetime object, indicating the start time of the data wanted
            stop:       datetime object, indicating the stop time of the data wanted
    Output: 
            df:         pandas dataframe, dataframe containing the data from the SiLK file 
'''
def getDataNetFlow(silkFile, start, stop):
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
        label.append(int(isAttackFlow(rec.sip, rec.dip, rec.stime, rec.etime)))

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

'''
    Get data from an raw SiLK file of NetFlow records
    Use the data to calculate the entropy and entropy rate of packet size
    Input:  
            silkFile:   string, path to the raw SiLK file sorted on time
            start:      datetime object, indicating the start time of the data wanted
            stop:       datetime object, indicating the stop time of the data wanted
            frequency:  timedelta object, frequency of entropy calculation
            interval:   timedelta object, size of the sliding window which the calculation is made on
    Output: 
            df:         pandas dataframe, dataframe containing the data from the SiLK file 
'''
def getEntropyDataNetFlow(silkFile, start, stop, frequency, interval):
    #Makes datetime objects of the input times
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

    packetSizeArray = []
    packetSizeRateArray = []

    packetNumberArray = []
    bytesArray = []

    timeArray = []
    #Instantiate variables
    sizes = []

    #Loop through all the flow records in the input file
    for rec in infile:
        if rec.etime >= stopTime:
            break
        if rec.stime < startTime:
            continue

        #Implement the sliding window
        if rec.stime > windowTime + frequency:
            lastSizes = 0
            for size in sizes:
                lastSizes += size
            thisMinuteSize = len(records) - lastSizes
            sizes.append(thisMinuteSize)
            windowTime += frequency
        #Aggregate flows into the specified time interval
        if rec.stime > startTime + interval:
            if len(records) == 0:
                startTime = startTime + frequency
                sizes.pop(0)
                records.append(rec)
                continue
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

            #Find the probability distribution based on how big the packets are this time interval
            PiPS,nps = packetSizeDistributionNetFlow(records)
            #Calculate the generalized entropy of this distribution
            entropyPacketSize = generalizedEntropy(10, PiPS)
            packetSizeArray.append(entropyPacketSize)
            #Calculate the generalized entropy rate of this distribution
            packetSizeRateArray.append(entropyPacketSize/nps)

            #Store the number of packets and bytes this time interval
            packetNumberArray.append(numberOfPackets(records))
            bytesArray.append(numberOfBytes(records))

            timeArray.append(startTime.strftime("%Y-%m-%d %H:%M"))
            #Push the sliding window
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)

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
     "number_of_icmp_packets": icmpPacketsArray,
     "packet_size_entropy": packetSizeArray,
     "packet_size_entropy_rate": packetSizeRateArray,
     "number_of_packets": packetNumberArray,
     "number_of_bytes": bytesArray
    })

    return entropy