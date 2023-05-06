import numpy as np
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
    print(start,stop)

    data = []
    i = 0
    for rec in infile:
        if rec.etime > stop:
            continue
        if rec.stime < start:
            continue

        data.append([rec.stime, rec.etime, int(rec.sip), int(rec.dip), rec.sport, rec.dport, rec.protocol, rec.packets, rec.bytes, 
                            int(rec.tcpflags.fin), int(rec.tcpflags.syn), int(rec.tcpflags.rst), int(rec.tcpflags.psh), int(rec.tcpflags.ack), 
                            int(rec.tcpflags.urg), int(rec.tcpflags.ece), int(rec.tcpflags.cwr), rec.duration_secs, int(rec.nhip), 
                            int(isAttackFlow(rec.sip, rec.dip, rec.stime, rec.etime))])
        if i % 1000000 == 0:
            print("i")
            print(i)
            print(rec.stime)
            print("\n")
        i+=1
    data = np.array(data)
    print(len(data))
    return data

'''
    Get data from an raw SiLK file of NetFlow records
    Input:  
            silkFile:   string, path to the raw SiLK file sorted on time
            start:      datetime object, indicating the start time of the data wanted
            stop:       datetime object, indicating the stop time of the data wanted
    Output: 
            df:         pandas dataframe, dataframe containing the data from the SiLK file 
'''
def getDataNetFlowNoIP(silkFile, start, stop):
    infile = silkfile_open(silkFile, READ)
    print(start,stop)

    data = []
    i = 0
    for rec in infile:
        if rec.etime > stop:
            continue
        if rec.stime < start:
            continue

        data.append([rec.stime, rec.etime, rec.sport, rec.dport, rec.protocol, rec.packets, rec.bytes, 
                            int(rec.tcpflags.fin), int(rec.tcpflags.syn), int(rec.tcpflags.rst), int(rec.tcpflags.psh), int(rec.tcpflags.ack), 
                            int(rec.tcpflags.urg), int(rec.tcpflags.ece), int(rec.tcpflags.cwr), rec.duration_secs, 
                            int(isAttackFlow(rec.sip, rec.dip, rec.stime, rec.etime))])
        i+=1
    data = np.array(data)
    print(len(data))
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
    starting = startTime
    pushed = False
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    records = []
    #Instantiate variables
    sizes = []

    data = []
    attackFlows = []
    print(start, stop)
    counter = 0
    #Loop through all the flow records in the input file
    for rec in infile:
        if rec.etime > stopTime:
            continue
        if rec.stime < startTime:
            continue
        if rec.stime >= starting and not pushed:
            startTime = rec.stime.replace(microsecond = 0, second = 0)
            pushed = True
        #Implement the sliding window
        if rec.stime > windowTime + frequency:
            lastSizes  = sum(sizes)
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

            #Find the probability distribution based on how many packets there is in each destination flow in this time interval
            PiDIP, nd = ipDestinationDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropyDip = generalizedEntropy(10,PiDIP)
            
            #Find the probability distribution based on how many packets there is in each bi-directional flow in this time interval
            PiF, nf = flowDistribution(records)
            #Calculate the generalized entropy of this distribution
            entropyFlow = generalizedEntropy(10, PiF)

            #Find the ratio of ICMP packets in this time interval
            icmpRatio, icmpPackets = icmpDistribution(records)

            #Find the probability distribution based on how big the packets are this time interval
            PiPS,nps = packetSizeDistributionNetFlow(records)
            #Calculate the generalized entropy of this distribution
            entropyPacketSize = generalizedEntropy(10, PiPS)
            if counter == 0:
                timeInterval = pd.Interval(pd.Timestamp(startTime), pd.Timestamp(rec.stime.replace(microsecond = 0, second = 0)), closed="both")
            else:
                timeInterval = pd.Interval(pd.Timestamp(rec.stime.replace(microsecond = 0, second = 0) - frequency), pd.Timestamp(rec.stime.replace(microsecond = 0, second = 0)), closed="right")
            label = 0
            for timestamp in attackFlows:
                if timestamp in timeInterval:
                    label = 1
            
            data.append([timeInterval, entropySip, entropySip/ns, entropyDip, entropyDip/nd, entropyFlow, 
                                entropyFlow/nf, nf, icmpRatio, icmpPackets, entropyPacketSize, entropyPacketSize/nps, 
                                numberOfPackets(records), numberOfBytes(records), label])

            #Push the sliding window
            startTime = startTime + frequency
            records = records[sizes[0]:]
            sizes.pop(0)
            counter += 1
        records.append(rec)
        #Check if it is an attack flow
        if isAttackFlow(rec.sip, rec.dip, rec.stime, rec.etime):
            attackFlows.append(rec.stime)

    data = np.array(data)
    print(len(data))
    return data