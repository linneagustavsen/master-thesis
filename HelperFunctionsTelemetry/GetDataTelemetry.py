from influxdb_client import InfluxDBClient
from .Distributions import *
from .GeneralizedEntropy import *
import math
import pandas as pd
from silk import *
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