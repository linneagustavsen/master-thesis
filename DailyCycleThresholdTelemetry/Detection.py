from influxdb_client import InfluxDBClient
from influxdb_client.client.write_api import SYNCHRONOUS
import json

#Set up a connection with the database
client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

def detection(systemId, if_name, field):
    #Open json file with threshold values
    json_file_mean_var = open("DailyCycleThresholdTelemetry/Thresholds/"+ str(systemId) + "." + str(if_name).replace("/","-") + "." + str(field)+"stdev.json", "r")
    json_object_mean_var = json.load(json_file_mean_var)
    json_file_mean_var.close()
    f = open("DailyCycleThresholdTelemetry/Detections/"+ str(systemId) + "." + str(if_name).replace("/","-") + "." + str(field)+"stdev17.txt", "a")

    query_api = client.query_api()

    #Query to get all outgoing packet/sec rates from one link in the period of detection
    query = 'from(bucket: "skogul/1mnd")\
            |> range(start: 2022-10-13T00:00:00Z, stop: 2022-10-20T00:00:00Z)\
            |> filter(fn: (r) => r["systemId"] == "' + systemId + '")\
            |> filter(fn: (r) => r["if_name"] == "' + if_name + '")\
            |> filter(fn: (r) => r["_field"] == "' + field + '")\
            |> group()        \
            |> keep(columns: ["_value", "_time"])'

    #Make a flux table list from the output of the query
    tables = query_api.query(query=query)
    f.write("Deviation score, Time, Value, Mean, Variance")
    #Loop through all the tables and the rows and check their deviation from the threshold values
    #Alert detection system if the deviation is higher than a predetermined value
    for table in tables:
        for row in table.records:
            mean_row = json_object_mean_var["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)]["mean"]
            variance_row = json_object_mean_var["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)]["variance"]
            
            deviation = (row.values["_value"]- mean_row)/variance_row

            if deviation > 17:
                f.write("\n" + str(deviation) + "," + str(row.values["_time"]) + "," +str( row.values["_value"]) + ","+str(mean_row) + "," +str( variance_row))
                #print("Deviation score",deviation, "at", row.values["_time"] )
    f.close()

detection("trd-gw", "xe-0/1/0", "egress_stats__if_1sec_pkts")
detection("trd-gw", "xe-0/1/0", "ingress_stats__if_1sec_pkts")
detection("trd-gw", "et-11/0/0", "ingress_stats__if_1sec_pkts")
detection("trd-gw", "et-11/0/0", "egress_stats__if_1sec_pkts")
detection("hmg9-gw1", "et-0/1/4", "ingress_stats__if_1sec_pkts")
detection("hmg9-gw1", "et-0/1/4", "egress_stats__if_1sec_pkts")
detection("hovedbygget-gw", "et-11/0/2", "egress_stats__if_1sec_pkts")
detection("hovedbygget-gw", "et-11/0/2", "ingress_stats__if_1sec_pkts")
