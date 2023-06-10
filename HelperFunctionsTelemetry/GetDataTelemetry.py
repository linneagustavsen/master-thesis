from influxdb_client import InfluxDBClient

from HelperFunctions.Distributions import packetSizeDistribution
from HelperFunctions.GeneralizedEntropy import generalizedEntropy
import math
import pandas as pd
from silk import *

from HelperFunctions.IsAttack import isAttack
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
def getData(start, stop, bucket, systemId, fields):
    client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

    query_api = client.query_api()
    columns = ["_time"]

    if systemId == "hoytek-gw2":
        query = 'data = (startTime, stopTime, field, fieldName) =>\
                    from(bucket: "' + bucket +'")\
                        |> range(start: startTime, stop: stopTime)\
                        |> filter(fn: (r) => r["link_name"] == "forde-hoytek" or r["link_name"] == "hovedbygget-hoytek"  or r["link_name"] == "hovedbygget-hoytek2" or r["link_name"] == "hovedbygget-hoytek3" or r["link_name"] == "tullin-hoytek" or r["link_name"] =="bergen-hoytek3" or r["link_name"] == "alesund-hoytek" or r["link_name"] == "hoytek-gw1.hoytek-gw2")\
                        |> filter(fn: (r) => r["_field"] == field )\
                        |> group()\
                        |> sort(columns: ["_time"])\
                        |> aggregateWindow(every: 2s, fn: sum, createEmpty: false)\
                        |> set(key: "_field", value: fieldName)'
        if len(fields) > 1:
            query += 'union(\
                    tables: ['
            for i in range(len(fields)):
                if "ingress" in fields[i]:
                    fieldName = fields[i].replace("ingress", "egress")
                elif "egress" in fields[i]:
                    fieldName = fields[i].replace("egress", "ingress")
                query += 'data(startTime:'+start + ', stopTime:'+stop + ', field:"'+fieldName+'", fieldName: "'+ fields[i]+ '"),'
                columns.append(fields[i])
            
                
            query += '],)'
        else:
            if "ingress" in fields[0]:
                fieldName = fields[0].replace("ingress", "egress")
            elif "egress" in fields[0]:
                fieldName = fields[0].replace("egress", "ingress")
            query += 'data(startTime:'+start + ', stopTime:'+stop + ', field:"'+fieldName+'", fieldName: "'+ fields[0]+ '")'
            
            columns.append(fields[0])
    
    elif systemId == "narvik-gw4":
        query = 'data = (startTime, stopTime, field, fieldName) =>\
                    from(bucket: "' + bucket +'")\
                        |> range(start: startTime, stop: stopTime)\
                        |> filter(fn: (r) => r["link_name"] == "tromso-narvik3" or r["link_name"] == "narvik-gw3.narvik-gw4" or r["link_name"] == "bodo-narvik" or r["link_name"] == "kommunevn-narvik")\
                        |> filter(fn: (r) => r["_field"] == field )\
                        |> group()\
                        |> sort(columns: ["_time"])\
                        |> aggregateWindow(every: 2s, fn: sum, createEmpty: false)\
                        |> set(key: "_field", value: fieldName)'
        if len(fields) > 1:
            query += 'union(\
                    tables: ['
            for i in range(len(fields)):
                if "ingress" in fields[i]:
                    fieldName = fields[i].replace("ingress", "egress")
                elif "egress" in fields[i]:
                    fieldName = fields[i].replace("egress", "ingress")
                query += 'data(startTime:'+start + ', stopTime:'+stop + ', field:"'+fieldName+'", fieldName: "'+ fields[i]+ '"),'
                columns.append(fields[i])
            
                
            query += '],)'
        else:
            if "ingress" in fields[0]:
                fieldName = fields[0].replace("ingress", "egress")
            elif "egress" in fields[0]:
                fieldName = fields[0].replace("egress", "ingress")
            query += 'data(startTime:'+start + ', stopTime:'+stop + ', field:"'+fieldName+'", fieldName: "'+ fields[0]+ '")'

            columns.append(fields[0])
    else: 
        query = 'data = (startTime, stopTime, systemId, field) =>\
                    from(bucket: "' + bucket +'")\
                        |> range(start: startTime, stop: stopTime)\
                        |> filter(fn: (r) => r["systemId"] == systemId)\
                        |> filter(fn: (r) => r["_field"] == field )\
                        |> group()\
                        |> sort(columns: ["_time"])\
                        |> aggregateWindow(every: 2s, fn: sum, createEmpty: false)\
                        |> set(key: "_field", value: field)'
        if len(fields) > 1:
            query += 'union(\
                    tables: ['
            for i in range(len(fields)):
                query += 'data(startTime:'+start + ', stopTime:'+stop + ', systemId: "'+systemId+ '", field:"'+fields[i]+'"),'
                columns.append(fields[i])
            
                
            query += '],)'
        else:
            query += 'data(startTime:'+start + ', stopTime:'+stop + ', systemId: "'+systemId+ '", field:"'+fields[0]+'")'
            columns.append(fields[0])
    query += '|> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")\
        |> keep(columns: ' + str(columns).replace("'", '"') + ')'

    #Make a data frame from the output of the query
    df = query_api.query_data_frame(query=query)

    #Clean up dataframe
    if not df.empty:
        df = df.drop(columns=['result', 'table'])

    return df

def getDataBytes(start, stop, bucket, systemId, direction):
    client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

    query_api = client.query_api()

    #Build query for database
    if systemId == "hoytek-gw2":
        query = 'data = (startTime, stopTime, field, fieldName) =>\
                    from(bucket: "' + bucket +'")\
                        |> range(start: startTime, stop: stopTime)\
                        |> filter(fn: (r) => r["link_name"] == "forde-hoytek" or r["link_name"] == "hovedbygget-hoytek"  or r["link_name"] == "hovedbygget-hoytek2" or r["link_name"] == "hovedbygget-hoytek3" or r["link_name"] == "tullin-hoytek" or r["link_name"] =="bergen-hoytek3" or r["link_name"] == "alesund-hoytek" or r["link_name"] == "hoytek-gw1.hoytek-gw2")\
                        |> filter(fn: (r) => r["_field"] == field )\
                        |> group()\
                        |> sort(columns: ["_time"])\
                        |> aggregateWindow(every: 2s, fn: sum, createEmpty: false)\
                        |> set(key: "_field", value: "bytes")'

        if direction == "in":
            query += 'data(startTime:'+start + ', stopTime:'+stop + ', field:"egress_stats__if_1sec_octets", fieldName: "ingress_stats__if_1sec_octets")'
        elif direction == "out":
            query += 'data(startTime:'+start + ', stopTime:'+stop + ', field:"ingress_stats__if_1sec_octets", fieldName: "egress_stats__if_1sec_octets")'

    elif systemId == "narvik-gw4":
        query = 'data = (startTime, stopTime, field, fieldName) =>\
                    from(bucket: "' + bucket +'")\
                        |> range(start: startTime, stop: stopTime)\
                        |> filter(fn: (r) => r["link_name"] == "tromso-narvik3" or r["link_name"] == "narvik-gw3.narvik-gw4" or r["link_name"] == "bodo-narvik" or r["link_name"] == "kommunevn-narvik")\
                        |> filter(fn: (r) => r["_field"] == field )\
                        |> group()\
                        |> sort(columns: ["_time"])\
                        |> aggregateWindow(every: 2s, fn: sum, createEmpty: false)\
                        |> set(key: "_field", value: "bytes")'
        if direction == "in":
            query += 'data(startTime:'+start + ', stopTime:'+stop + ', field:"egress_stats__if_1sec_octets", fieldName: "ingress_stats__if_1sec_octets")'
        elif direction == "out":
            query += 'data(startTime:'+start + ', stopTime:'+stop + ', field:"ingress_stats__if_1sec_octets", fieldName: "egress_stats__if_1sec_octets")'
    else:
        query = 'data = (startTime, stopTime, systemId, field) =>\
                    from(bucket: "' + bucket +'")\
                        |> range(start: startTime, stop: stopTime)\
                        |> filter(fn: (r) => r["systemId"] == systemId)\
                        |> filter(fn: (r) => r["_field"] == field )\
                        |> group()\
                        |> sort(columns: ["_time"])\
                        |> aggregateWindow(every: 2s, fn: sum, createEmpty: false)\
                        |> set(key: "_field", value: "bytes")'
       
        if direction == "out":
            query += 'data(startTime:'+start + ', stopTime:'+stop + ', systemId: "'+systemId+ '", field:"egress_stats__if_1sec_octets")'
        elif direction == "in":
            query += 'data(startTime:'+start + ', stopTime:'+stop + ', systemId: "'+systemId+ '", field:"ingress_stats__if_1sec_octets")'

    query += '|> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")'
    
    #Make a data frame from the output of the query
    df = query_api.query_data_frame(query=query)

    #Clean up dataframe
    if not df.empty:
        df = df.drop(columns=['result', 'table'])

    return df

def getDataPackets(start, stop, bucket, systemId, direction):
    client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

    query_api = client.query_api()

    #Build query for database
    if systemId == "hoytek-gw2":
        query = 'data = (startTime, stopTime, field, fieldName) =>\
                    from(bucket: "' + bucket +'")\
                        |> range(start: startTime, stop: stopTime)\
                        |> filter(fn: (r) => r["link_name"] == "forde-hoytek" or r["link_name"] == "hovedbygget-hoytek"  or r["link_name"] == "hovedbygget-hoytek2" or r["link_name"] == "hovedbygget-hoytek3" or r["link_name"] == "tullin-hoytek" or r["link_name"] =="bergen-hoytek3" or r["link_name"] == "alesund-hoytek" or r["link_name"] == "hoytek-gw1.hoytek-gw2")\
                        |> filter(fn: (r) => r["_field"] == field )\
                        |> group()\
                        |> sort(columns: ["_time"])\
                        |> aggregateWindow(every: 2s, fn: sum, createEmpty: false)\
                        |> set(key: "_field", value: "packets")'

        if direction == "in":
            query += 'data(startTime:'+start + ', stopTime:'+stop + ', field:"egress_stats__if_1sec_pkts", fieldName: "ingress_stats__if_1sec_pkts")'
        elif direction == "out":
            query += 'data(startTime:'+start + ', stopTime:'+stop + ', field:"ingress_stats__if_1sec_pkts", fieldName: "egress_stats__if_1sec_pkts")'

    elif systemId == "narvik-gw4":
        query = 'data = (startTime, stopTime, field, fieldName) =>\
                    from(bucket: "' + bucket +'")\
                        |> range(start: startTime, stop: stopTime)\
                        |> filter(fn: (r) => r["link_name"] == "tromso-narvik3" or r["link_name"] == "narvik-gw3.narvik-gw4" or r["link_name"] == "bodo-narvik" or r["link_name"] == "kommunevn-narvik")\
                        |> filter(fn: (r) => r["_field"] == field )\
                        |> group()\
                        |> sort(columns: ["_time"])\
                        |> aggregateWindow(every: 2s, fn: sum, createEmpty: false)\
                        |> set(key: "_field", value: "packets")'

        if direction == "in":
            query += 'data(startTime:'+start + ', stopTime:'+stop + ', field:"egress_stats__if_1sec_pkts", fieldName: "ingress_stats__if_1sec_pkts")'
        elif direction == "out":
            query += 'data(startTime:'+start + ', stopTime:'+stop + ', field:"ingress_stats__if_1sec_pkts", fieldName: "egress_stats__if_1sec_pkts")'

    else:
        query = 'data = (startTime, stopTime, systemId, field) =>\
                    from(bucket: "' + bucket +'")\
                        |> range(start: startTime, stop: stopTime)\
                        |> filter(fn: (r) => r["systemId"] == systemId)\
                        |> filter(fn: (r) => r["_field"] == field )\
                        |> group()\
                        |> sort(columns: ["_time"])\
                        |> aggregateWindow(every: 2s, fn: sum, createEmpty: false)\
                        |> set(key: "_field", value: "packets")'

        if direction == "out":
            query += 'data(startTime:'+start + ', stopTime:'+stop + ', systemId: "'+systemId+ '", field:"egress_stats__if_1sec_pkts")'
        elif direction == "in":
            query += 'data(startTime:'+start + ', stopTime:'+stop + ', systemId: "'+systemId+ '", field:"ingress_stats__if_1sec_pkts")'

    query+= '|> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")'

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
def getDataTables(start, stop, systemId, bucket, field):
    client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

    query_api = client.query_api()

    #Build query
    query = 'from(bucket: "' + bucket + '")\
            |> range(start:'+start + ', stop:'+stop + ')\
            |> filter(fn: (r) => r["systemId"] == "' + systemId + '")\
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
def getEntropyData(start, stop, systemId,  bucket, interval, frequency):
    intervalTime = (stop - start).total_seconds()/frequency.total_seconds()

    packetSizeArrayin = []
    packetSizeRateArrayin = []
    packetSizeArrayout = []
    packetSizeRateArrayout = []
    timeArray = []
    labels = []
    startTime = start
    counter = 0
    for i in range(math.ceil(intervalTime)):
        stopTime = startTime + interval
        #Get data for a specified time interval
        df_bytes_ingress = getDataBytes(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), "april", systemId, "in")
        df_bytes_egress = getDataBytes(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), "april", systemId, "out")
        df_packets_ingress = getDataPackets(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), "april", systemId, "in")
        df_packets_egress = getDataPackets(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), "april", systemId, "out")
        #If there is no data for this interval we skip the calculations
        if df_bytes_ingress.empty or df_packets_ingress.empty or df_bytes_egress.empty or df_packets_egress.empty:
            startTime = startTime + frequency
            continue
        df_bytes_ingress = df_bytes_ingress["bytes"].to_numpy()
        df_packets_ingress = df_packets_ingress["packets"].to_numpy()
        df_bytes_egress = df_bytes_egress["bytes"].to_numpy()
        df_packets_egress = df_packets_egress["packets"].to_numpy()

        if counter == 0:
            timeInterval = pd.Interval(pd.Timestamp(startTime), pd.Timestamp(stopTime), closed="both")
        else:
            timeInterval =pd.Interval(pd.Timestamp(stopTime - frequency),pd.Timestamp(stopTime), closed="right") 
   
        timeArray.append(timeInterval)

        ##Find the probability distribution based on how big the packets are this time interval
        PiPS,nps = packetSizeDistribution(df_bytes_ingress, df_packets_ingress)
        #Calculate the generalized entropy of this distribution
        entropyPacketSize = generalizedEntropy(10, PiPS)
        packetSizeArrayin.append(entropyPacketSize)
        #Calculate the generalized entropy rate of this distribution
        packetSizeRateArrayin.append(entropyPacketSize/nps)

        #Find the probability distribution based on how big the packets are this time interval
        PiPS,nps = packetSizeDistribution(df_bytes_egress, df_packets_egress)
        #Calculate the generalized entropy of this distribution
        entropyPacketSize = generalizedEntropy(10, PiPS)
        packetSizeArrayout.append(entropyPacketSize)
        #Calculate the generalized entropy rate of this distribution
        packetSizeRateArrayout.append(entropyPacketSize/nps)
        labels.append(int(isAttack(timeInterval.left, timeInterval.right)))
        
        #Push the start time by the specified frequency
        startTime = startTime + frequency
        counter +=1
    entropy = pd.DataFrame(
    {"time": timeArray,
     "entropy_packet_size_ingress": packetSizeArrayin,
     "entropy_rate_packet_size_ingress": packetSizeRateArrayin,
     "entropy_packet_size_egress": packetSizeArrayout,
     "entropy_rate_packet_size_egress": packetSizeRateArrayout,
     "labels": labels
    })

    return entropy