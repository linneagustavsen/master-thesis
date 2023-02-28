from influxdb_client import InfluxDBClient
from datetime import datetime,timedelta
from Distributions import *
import math
import numpy as np
from GeneralizedEntropy import generalizedEntropy
import pandas as pd
'''
start: datetime
stop: datetime
systemId: string
if_name: string
fields: array of strings
'''

def getData(start, stop, systemId, if_name, fields):
    client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

    query_api = client.query_api()
    columns = ["_time"]

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
    |> keep(columns: ' + str(columns).replace("'", '"') + ')'

    #Make a data frame from the output of the query
    df = query_api.query_data_frame(query=query)

    if not df.empty:
        df = df.drop(columns=['result', 'table'])

    return df

def getEntropyData(start, stop, systemId, if_name):
    intervalTime = (stop - start).total_seconds()/60

    packetSizeArray = []
    packetSizeRateArray = []
    timeArray = []
    startTime = start

    for i in range(math.ceil(intervalTime)):
        stopTime = startTime + timedelta(minutes = 5)
        #Get data for a specified time interval
        df = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),systemId, if_name, ["egress_stats__if_1sec_octets", "egress_stats__if_1sec_pkts"])
        
        #If there is not enough data points the minute is skipped
        if df.empty:
            #Push the start time by the specified frequency
            startTime = startTime + timedelta(minutes = 1)
            continue
        egressBytes = df["egress_stats__if_1sec_octets"].to_numpy()
        egressPackets = df["egress_stats__if_1sec_pkts"].to_numpy()

        timeArray.append(startTime.strftime("%Y-%m-%d %H:%M"))

        #Find the probability distribution based on how big the packets are this time interval
        PiPS,nd = packetSizeDistribution(egressBytes, egressPackets)
        #Calculate the generalized entropy of this distribution
        entropyPacketSize = generalizedEntropy(10, PiPS)
        packetSizeArray.append(entropyPacketSize)

        #Calculate the generalized entropy rate of this distribution
        entropyRatePacketSize = entropyPacketSize/nd
        packetSizeRateArray.append(entropyRatePacketSize)

        #Push the start time by the specified frequency
        startTime = startTime + timedelta(minutes = 1)

    entropy = pd.DataFrame(
    {"_time": timeArray,
     "entropy_packet_size": packetSizeArray,
     "entropy_rate_packet_size": packetSizeRateArray
    })
    entropy.to_pickle("TelemetryKmeans/entropy" + str(start) + ".pkl")

    return entropy