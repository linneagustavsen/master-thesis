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
        query = 'data = (startTime, stopTime, link_name, field, fieldName) =>\
                    from(bucket: "' + bucket +'")\
                        |> range(start: startTime, stop: stopTime)\
                        |> filter(fn: (r) => r["link_name"] == link_name)\
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
                query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"'+fieldName+'", link_name: "forde-hoytek", fieldName: "'+ fields[i]+ '"),'
                query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"'+fieldName+'", link_name: "hovedbygget-hoytek", fieldName: "'+ fields[i]+ '"),'
                query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"'+fieldName+'", link_name: "hovedbygget-hoytek2", fieldName: "'+ fields[i]+ '"),'
                query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"'+fieldName+'", link_name: "hovedbygget-hoytek3", fieldName: "'+ fields[i]+ '"),'
                query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"'+fieldName+'", link_name: "tullin-hoytek", fieldName: "'+ fields[i]+ '"),'
                query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"'+fieldName+'", link_name: "bergen-hoytek3", fieldName: "'+ fields[i]+ '"),'
                query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"'+fieldName+'", link_name: "alesund-hoytek", fieldName: "'+ fields[i]+ '"),'
                query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"'+fieldName+'", link_name: "hoytek-gw1.hoytek-gw2", fieldName: "'+ fields[i]+ '"),'
                columns.append(fields[i])
            
                
            query += '],)'
        else:
            query += 'union(\
                    tables: ['
            if "ingress" in fields[0]:
                fieldName = fields[0].replace("ingress", "egress")
            elif "egress" in fields[0]:
                fieldName = fields[0].replace("egress", "ingress")
            query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"'+fieldName+'", link_name: "forde-hoytek", fieldName: "'+ fields[0]+ '"),'
            query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"'+fieldName+'", link_name: "hovedbygget-hoytek", fieldName: "'+ fields[0]+ '"),'
            query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"'+fieldName+'", link_name: "hovedbygget-hoytek2", fieldName: "'+ fields[0]+ '"),'
            query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"'+fieldName+'", link_name: "hovedbygget-hoytek3", fieldName: "'+ fields[0]+ '"),'
            query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"'+fieldName+'", link_name: "tullin-hoytek", fieldName: "'+ fields[0]+ '"),'
            query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"'+fieldName+'", link_name: "bergen-hoytek3", fieldName: "'+ fields[0]+ '"),'
            query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"'+fieldName+'", link_name: "alesund-hoytek", fieldName: "'+ fields[0]+ '"),'
            query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"'+fieldName+'", link_name: "hoytek-gw1.hoytek-gw2", fieldName: "'+ fields[0]+ '"),'
            query += '],)'
            columns.append(fields[0])
    
    elif systemId == "narvik-gw4":
        query = 'data = (startTime, stopTime, link_name, field, fieldName) =>\
                    from(bucket: "' + bucket +'")\
                        |> range(start: startTime, stop: stopTime)\
                        |> filter(fn: (r) => r["link_name"] == link_name)\
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
                query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"'+fieldName+'", link_name: "tromso-narvik3", fieldName: "'+ fields[i]+ '"),'
                query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"'+fieldName+'", link_name: "narvik-gw3.narvik-gw4", fieldName: "'+ fields[i]+ '"),'
                query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"'+fieldName+'", link_name: "kommunevn-narvik", fieldName: "'+ fields[i]+ '"),'
                query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"'+fieldName+'", link_name: "bodo-narvik", fieldName: "'+ fields[i]+ '"),'
                columns.append(fields[i])
            
                
            query += '],)'
        else:
            query += 'union(\
                    tables: ['
            if "ingress" in fields[0]:
                fieldName = fields[0].replace("ingress", "egress")
            elif "egress" in fields[0]:
                fieldName = fields[0].replace("egress", "ingress")
            query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"'+fieldName+'", link_name: "tromso-narvik3", fieldName: "'+ fields[0]+ '"),'
            query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"'+fieldName+'", link_name: "narvik-gw3.narvik-gw4", fieldName: "'+ fields[0]+ '"),'
            query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"'+fieldName+'", link_name: "kommunevn-narvik", fieldName: "'+ fields[0]+ '"),'
            query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"'+fieldName+'", link_name: "bodo-narvik", fieldName: "'+ fields[0]+ '"),'
            query += '],)'
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
                query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', systemId: "'+systemId+ '", field:"'+fields[i]+'"),'
                columns.append(fields[i])
            
                
            query += '],)'
        else:
            query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', systemId: "'+systemId+ '", field:"'+fields[0]+'")'
            columns.append(fields[0])
    query += '|> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")\
        |> keep(columns: ' + str(columns).replace("'", '"') + ')'

    #Make a data frame from the output of the query
    df = query_api.query_data_frame(query=query)

    #Clean up dataframe
    if not df.empty:
        df = df.drop(columns=['result', 'table'])

    return df

def getDataBytes(start, stop, bucket, systemId):
    client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

    query_api = client.query_api()

    #Build query for database
    if systemId == "hoytek-gw2":
        query = 'data = (startTime, stopTime, link_name, field, fieldName) =>\
                    from(bucket: "' + bucket +'")\
                        |> range(start: startTime, stop: stopTime)\
                        |> filter(fn: (r) => r["link_name"] == link_name)\
                        |> filter(fn: (r) => r["_field"] == field )\
                        |> group()\
                        |> sort(columns: ["_time"])\
                        |> aggregateWindow(every: 2s, fn: sum, createEmpty: false)\
                        |> set(key: "_field", value: fieldName)'

        query += 'union(\
                tables: ['
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"egress_stats__if_1sec_octets", link_name: "forde-hoytek", fieldName: "ingress_stats__if_1sec_octets"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"egress_stats__if_1sec_octets", link_name: "hovedbygget-hoytek", fieldName: "ingress_stats__if_1sec_octets"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"egress_stats__if_1sec_octets", link_name: "hovedbygget-hoytek2", fieldName: "ingress_stats__if_1sec_octets"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"egress_stats__if_1sec_octets", link_name: "hovedbygget-hoytek3", fieldName: "ingress_stats__if_1sec_octets"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"egress_stats__if_1sec_octets", link_name: "tullin-hoytek", fieldName: "ingress_stats__if_1sec_octets"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"egress_stats__if_1sec_octets", link_name: "bergen-hoytek3", fieldName: "ingress_stats__if_1sec_octets"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"egress_stats__if_1sec_octets", link_name: "alesund-hoytek", fieldName: "ingress_stats__if_1sec_octets"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"egress_stats__if_1sec_octets", link_name: "hoytek-gw1.hoytek-gw2", fieldName: "ingress_stats__if_1sec_octets"),'

        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"ingress_stats__if_1sec_octets", link_name: "forde-hoytek", fieldName: "egress_stats__if_1sec_octets"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"ingress_stats__if_1sec_octets", link_name: "hovedbygget-hoytek", fieldName: "egress_stats__if_1sec_octets"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"ingress_stats__if_1sec_octets", link_name: "hovedbygget-hoytek2", fieldName: "egress_stats__if_1sec_octets"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"ingress_stats__if_1sec_octets", link_name: "hovedbygget-hoytek3", fieldName: "egress_stats__if_1sec_octets"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"ingress_stats__if_1sec_octets", link_name: "tullin-hoytek", fieldName: "egress_stats__if_1sec_octets"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"ingress_stats__if_1sec_octets", link_name: "bergen-hoytek3", fieldName: "egress_stats__if_1sec_octets"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"ingress_stats__if_1sec_octets", link_name: "alesund-hoytek", fieldName: "egress_stats__if_1sec_octets"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"ingress_stats__if_1sec_octets", link_name: "hoytek-gw1.hoytek-gw2", fieldName: "egress_stats__if_1sec_octets"),'
        query += '],)'
    elif systemId == "narvik-gw4":
        query = 'data = (startTime, stopTime, link_name, field, fieldName) =>\
                    from(bucket: "' + bucket +'")\
                        |> range(start: startTime, stop: stopTime)\
                        |> filter(fn: (r) => r["link_name"] == link_name)\
                        |> filter(fn: (r) => r["_field"] == field )\
                        |> group()\
                        |> sort(columns: ["_time"])\
                        |> aggregateWindow(every: 2s, fn: sum, createEmpty: false)\
                        |> set(key: "_field", value: fieldName)'
        query += 'union(\
                tables: ['
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"egress_stats__if_1sec_octets", link_name: "tromso-narvik3", fieldName: "ingress_stats__if_1sec_octets"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"egress_stats__if_1sec_octets", link_name: "narvik-gw3.narvik-gw4", fieldName: "ingress_stats__if_1sec_octets"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"egress_stats__if_1sec_octets", link_name: "kommunevn-narvik", fieldName: "ingress_stats__if_1sec_octets"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"egress_stats__if_1sec_octets", link_name: "bodo-narvik", fieldName: "ingress_stats__if_1sec_octets"),'

        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"ingress_stats__if_1sec_octets", link_name: "tromso-narvik3", fieldName: "egress_stats__if_1sec_octets"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"ingress_stats__if_1sec_octets", link_name: "narvik-gw3.narvik-gw4", fieldName: "egress_stats__if_1sec_octets"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"ingress_stats__if_1sec_octets", link_name: "kommunevn-narvik", fieldName: "egress_stats__if_1sec_octets"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"ingress_stats__if_1sec_octets", link_name: "bodo-narvik", fieldName: "egress_stats__if_1sec_octets"),'
        query += '],)'
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
        query += 'union(\
                    tables: [\
                    data(startTime: ' + start + ', stopTime: ' + stop + ', systemId: "'+systemId+ '", field:"egress_stats__if_1sec_octets"),\
                    data(startTime: ' + start + ', stopTime: ' + stop + ', systemId: "'+systemId+ '", field:"ingress_stats__if_1sec_octets"),],)'
    query += '|> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")\
            |> map(fn: (r) => ({_time: r._time, bytes: r.egress_stats__if_1sec_octets + r.ingress_stats__if_1sec_octets}))'

    #Make a data frame from the output of the query
    df = query_api.query_data_frame(query=query)

    #Clean up dataframe
    if not df.empty:
        df = df.drop(columns=['result', 'table'])

    return df

def getDataPackets(start, stop, bucket, systemId):
    client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

    query_api = client.query_api()

    #Build query for database
    if systemId == "hoytek-gw2":
        query = 'data = (startTime, stopTime, link_name, field, fieldName) =>\
                    from(bucket: "' + bucket +'")\
                        |> range(start: startTime, stop: stopTime)\
                        |> filter(fn: (r) => r["link_name"] == link_name)\
                        |> filter(fn: (r) => r["_field"] == field )\
                        |> group()\
                        |> sort(columns: ["_time"])\
                        |> aggregateWindow(every: 2s, fn: sum, createEmpty: false)\
                        |> set(key: "_field", value: fieldName)'

        query += 'union(\
                tables: ['
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"egress_stats__if_1sec_pkts", link_name: "forde-hoytek", fieldName: "ingress_stats__if_1sec_pkts"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"egress_stats__if_1sec_pkts", link_name: "hovedbygget-hoytek", fieldName: "ingress_stats__if_1sec_pkts"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"egress_stats__if_1sec_pkts", link_name: "hovedbygget-hoytek2", fieldName: "ingress_stats__if_1sec_pkts"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"egress_stats__if_1sec_pkts", link_name: "hovedbygget-hoytek3", fieldName: "ingress_stats__if_1sec_pkts"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"egress_stats__if_1sec_pkts", link_name: "tullin-hoytek", fieldName: "ingress_stats__if_1sec_pkts"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"egress_stats__if_1sec_pkts", link_name: "bergen-hoytek3", fieldName: "ingress_stats__if_1sec_pkts"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"egress_stats__if_1sec_pkts", link_name: "alesund-hoytek", fieldName: "ingress_stats__if_1sec_pkts"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"egress_stats__if_1sec_pkts", link_name: "hoytek-gw1.hoytek-gw2", fieldName: "ingress_stats__if_1sec_pkts"),'

        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"ingress_stats__if_1sec_pkts", link_name: "forde-hoytek", fieldName: "egress_stats__if_1sec_pkts"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"ingress_stats__if_1sec_pkts", link_name: "hovedbygget-hoytek", fieldName: "egress_stats__if_1sec_pkts"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"ingress_stats__if_1sec_pkts", link_name: "hovedbygget-hoytek2", fieldName: "egress_stats__if_1sec_pkts"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"ingress_stats__if_1sec_pkts", link_name: "hovedbygget-hoytek3", fieldName: "egress_stats__if_1sec_pkts"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"ingress_stats__if_1sec_pkts", link_name: "tullin-hoytek", fieldName: "egress_stats__if_1sec_pkts"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"ingress_stats__if_1sec_pkts", link_name: "bergen-hoytek3", fieldName: "egress_stats__if_1sec_pkts"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"ingress_stats__if_1sec_pkts", link_name: "alesund-hoytek", fieldName: "egress_stats__if_1sec_pkts"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"ingress_stats__if_1sec_pkts", link_name: "hoytek-gw1.hoytek-gw2", fieldName: "egress_stats__if_1sec_pkts"),'
        query += '],)'
    elif systemId == "narvik-gw4":
        query = 'data = (startTime, stopTime, link_name, field, fieldName) =>\
                    from(bucket: "' + bucket +'")\
                        |> range(start: startTime, stop: stopTime)\
                        |> filter(fn: (r) => r["link_name"] == link_name)\
                        |> filter(fn: (r) => r["_field"] == field )\
                        |> group()\
                        |> sort(columns: ["_time"])\
                        |> aggregateWindow(every: 2s, fn: sum, createEmpty: false)\
                        |> set(key: "_field", value: fieldName)'
        query += 'union(\
                tables: ['
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"egress_stats__if_1sec_pkts", link_name: "tromso-narvik3", fieldName: "ingress_stats__if_1sec_pkts"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"egress_stats__if_1sec_pkts", link_name: "narvik-gw3.narvik-gw4", fieldName: "ingress_stats__if_1sec_pkts"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"egress_stats__if_1sec_pkts", link_name: "kommunevn-narvik", fieldName: "ingress_stats__if_1sec_pkts"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"egress_stats__if_1sec_pkts", link_name: "bodo-narvik", fieldName: "ingress_stats__if_1sec_pkts"),'

        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"ingress_stats__if_1sec_pkts", link_name: "tromso-narvik3", fieldName: "egress_stats__if_1sec_pkts"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"ingress_stats__if_1sec_pkts", link_name: "narvik-gw3.narvik-gw4", fieldName: "egress_stats__if_1sec_pkts"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"ingress_stats__if_1sec_pkts", link_name: "kommunevn-narvik", fieldName: "egress_stats__if_1sec_pkts"),'
        query += 'data(startTime: ' + start + ', stopTime: ' + stop + ', field:"ingress_stats__if_1sec_pkts", link_name: "bodo-narvik", fieldName: "egress_stats__if_1sec_pkts"),'
        query += '],)'
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
        query += 'union(\
                    tables: [\
                    data(startTime: ' + start + ', stopTime: ' + stop + ', systemId: "'+systemId+ '", field:"egress_stats__if_1sec_pkts"),\
                    data(startTime: ' + start + ', stopTime: ' + stop + ', systemId: "'+systemId+ '", field:"ingress_stats__if_1sec_pkts"),],)'
    query+= '|> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")\
             |> map(fn: (r) => ({_time: r._time, packets: r.egress_stats__if_1sec_pkts + r.ingress_stats__if_1sec_pkts}))'


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
            |> range(start: ' + start + ', stop: ' + stop + ')\
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

    packetSizeArray = []
    packetSizeRateArray = []
    timeArray = []
    labels = []
    startTime = start
    counter = 0
    for i in range(math.ceil(intervalTime)):
        stopTime = startTime + interval
        #Get data for a specified time interval
        dfBytes = getDataBytes(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), bucket, systemId)
        dfPackets = getDataPackets(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), bucket, systemId)

        #If there is no data for this interval we skip the calculations
        if dfBytes.empty or dfPackets.empty:
            startTime = startTime + frequency
            continue
        dfBytes = dfBytes["bytes"].to_numpy()
        dfPackets = dfPackets["packets"].to_numpy()

        if counter == 0:
            timeInterval = pd.Interval(pd.Timestamp(startTime), pd.Timestamp(stopTime), closed="both")
        else:
            timeInterval =pd.Interval(pd.Timestamp(stopTime - frequency),pd.Timestamp(stopTime), closed="right") 
   
        timeArray.append(timeInterval)

        #Find the probability distribution based on how big the packets are this time interval
        PiPS,nps = packetSizeDistribution(dfBytes, dfPackets)
        #Calculate the generalized entropy of this distribution
        entropyPacketSize = generalizedEntropy(10, PiPS)
        packetSizeArray.append(entropyPacketSize)
        #Calculate the generalized entropy rate of this distribution
        packetSizeRateArray.append(entropyPacketSize/nps)
        labels.append(int(isAttack(timeInterval.left, timeInterval.right)))
        
        #Push the start time by the specified frequency
        startTime = startTime + frequency
        counter +=1
    entropy = pd.DataFrame(
    {"time": timeArray,
     "entropy_packet_size": packetSizeArray,
     "entropy_rate_packet_size": packetSizeRateArray,
     "labels": labels
    })

    return entropy