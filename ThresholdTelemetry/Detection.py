from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
import json
import numpy as np
from datetime import timezone
import time
start_time = time.time()

#Open json file with threshold values
json_file_mean_var = open("ThresholdTelemetry/RawValues/MeanVarValuesDenoisedNTNU.json", "r")
json_object_mean_var = json.load(json_file_mean_var)
json_file_mean_var.close()

#Set up a connection with the database
client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

query_api = client.query_api()

#Query to get all outgoing packet/sec rates from one link in the period of detection
query = 'from(bucket: "skogul/1mnd")\
        |> range(start: 2022-10-13T00:00:00Z, stop: 2022-10-20T00:00:00Z)\
        |> filter(fn: (r) => r["systemId"] == "trd-gw")\
        |> filter(fn: (r) => r["if_name"] == "xe-0/1/0")\
        |> filter(fn: (r) => r["_field"] == "egress_stats__if_1sec_pkts")\
        |> group()        \
        |> keep(columns: ["_value", "_time"])'

#Make a flux table list from the output of the query
tables = query_api.query(query=query)
print("Deviation score, Time, Value, Mean , Variance")
#Loop through all the tables and the rows and check their deviation from the threshold values
#Alert detection system if the deviation is higher than a predetermined value
for table in tables:
    for row in table.records:
        mean_row = json_object_mean_var["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)]["mean"]
        variance_row = json_object_mean_var["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)]["variance"]
        deviation = (row.values["_value"]- mean_row)/variance_row

        if deviation > 0.002:
            print(deviation, ",", row.values["_time"],",", row.values["_value"], ",", mean_row, ",", variance_row)
            #print("Deviation score",deviation, "at", row.values["_time"] )

print("--- %s seconds ---" % (time.time() - start_time))