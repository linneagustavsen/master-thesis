from influxdb_client import InfluxDBClient
from .Distributions import *
from .GeneralizedEntropy import *
import math
import pandas as pd
from datetime import datetime
from silk import *
from .IsAttack import *

'''
    Get data from an InfluxDB
    Input:  
            start:      datetime object, indicating the start time of the data wanted
            stop:       datetime object, indicating the stop time of the data wanted
            systemId:   string, name of the system to collect from
            if_name:    string, interface name,
            fields:     list of strings, the fields to get from the database
    Output: 
            df:         pandas dataframe, dataframe containing the data from the database
'''
def getData(start, stop, systemId, if_name, fields):
    client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

    query_api = client.query_api()
    columns = ["_time"]

    #Build query for database
    query = 'from(bucket: "skogul/1mnd")\
                |> range(start: ' + start + ', stop: ' + stop + ')\
                |> filter(fn: (r) => r["systemId"] == "' + systemId + '")\
                |> filter(fn: (r) => r["if_name"] == "' + if_name + '")\
                |> filter(fn: (r) => '
    for i in range(len(fields)):
        query += 'r["_field"] == "' + fields[i] + '"'
        columns.append(fields[i])
        if len(fields) != 1 and i != len(fields)-1:
            query += ' or '
        
    query += ')\
    |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")\
    |> group()        \
    |> keep(columns: ' + str(columns).replace("'", '"') + ')'

    #Make a data frame from the output of the query
    df = query_api.query_data_frame(query=query)

    #Clean up dataframe
    if not df.empty:
        df = df.drop(columns=['result', 'table'])

    return df

'''
    Get data from an InfluxDB
    Input:  
            start:      datetime object, indicating the start time of the data wanted
            stop:       datetime object, indicating the stop time of the data wanted
            systemId:   string, name of the system to collect from
            if_name:    string, interface name,
            field:      string, the field to get from the database
    Output: 
            tables:     flux table list, table containing the data from the database
'''
def getDataTables(start, stop, systemId, if_name, field):
    client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

    query_api = client.query_api()

    #Build query
    query = 'from(bucket: "skogul/1mnd")\
            |> range(start: ' + start + ', stop: ' + stop + ')\
            |> filter(fn: (r) => r["systemId"] == "' + systemId + '")\
            |> filter(fn: (r) => r["if_name"] == "' + if_name + '")\
            |> filter(fn: (r) => r["_field"] == "' + field + '")\
            |> group()        \
            |> keep(columns: ["_value", "_time"])'

    #Make a flux table list from the output of the query
    tables = query_api.query(query=query)

    return tables

'''
    Get data from an InfluxDB
    Use the data to calculate the entropy and entropy rate of packet size
    Input:  
            start:      datetime object, indicating the start time of the data wanted
            stop:       datetime object, indicating the stop time of the data wanted
            systemId:   string, name of the system to collect from
            if_name:    string, interface name,
    Output: 
            entropy:    pandas dataframe, dataframe containing the entropy of packet size and the entropy rate of packet size
'''
def getEntropyData(start, stop, systemId, if_name, interval, frequency):
    intervalTime = (stop - start).total_seconds()/frequency.total_seconds()

    packetSizeArray = []
    packetSizeRateArray = []
    timeArray = []
    startTime = start

    for i in range(math.ceil(intervalTime)):
        stopTime = startTime + interval
        #Get data for a specified time interval
        df = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),systemId, if_name, ["egress_stats__if_1sec_octets", "egress_stats__if_1sec_pkts"])
        
        #If there is not enough data points the minute is skipped
        if df.empty:
            #Push the start time by the specified frequency
            startTime = startTime + frequency
            continue
        egressBytes = df["egress_stats__if_1sec_octets"].to_numpy()
        egressPackets = df["egress_stats__if_1sec_pkts"].to_numpy()
        
        timeArray.append(startTime.strftime("%Y-%m-%d %H:%M"))

        #Find the probability distribution based on how big the packets are this time interval
        PiPS,nps = packetSizeDistribution(egressBytes, egressPackets)
        #Calculate the generalized entropy of this distribution
        entropyPacketSize = generalizedEntropy(10, PiPS)
        packetSizeArray.append(entropyPacketSize)
        #Calculate the generalized entropy rate of this distribution
        packetSizeRateArray.append(entropyPacketSize/nps)

        #Push the start time by the specified frequency
        startTime = startTime + frequency

    entropy = pd.DataFrame(
    {"_time": timeArray,
     "entropy_packet_size": packetSizeArray,
     "entropy_rate_packet_size": packetSizeRateArray
    })

    return entropy

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
    i = 0
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
            i += 1
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