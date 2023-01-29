
'''
for i in rows in the last batch of data:
    check which weekday it is to compare to the right bucket
    check which hour minute and second it is to get the right row from that weekday bucket

    P = get mean from that row from the bucket
    V = get variance from that row from the bucket
     
    D = (the new measurement like number of packets - P)/V
    Add D to a new bucket or array or dictionary or just check the threshold here
    if D >= trigger value (test it out a bit):
        send alert to alert correlator
        write to file or use MQTT
'''


from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
import json
import numpy as np
from datetime import timezone

json_file_mean_var = open("/home/linneafg/Code/master-thesis/MeanVarValuesDeNoised.json", "r")
json_object_mean_var = json.load(json_file_mean_var)
json_file_mean_var.close()

client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

query_api = client.query_api()

query = 'import "date" from(bucket: "skogul/1mnd")\
        |> range(start: 2022-10-17T00:00:00Z, stop: 2022-10-21T01:00:00Z)\
        |> filter(fn: (r) => r["link_name"] == "alta-narvik")\
        |> filter(fn: (r) => r["_field"] == "egress_stats__if_1sec_pkts")\
        |> keep(columns: ["_value", "_time"])'


tables = query_api.query(query=query)
for table in tables:
    for row in table.records:
        mean_row = json_object_mean_var["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)]["mean"]
        variance_row = json_object_mean_var["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)]["variance"]
        D = (row.values["_value"]- mean_row)/variance_row
        #print(D)
        if D > 0.05:
            print("Deviation score",D, "at", row.values["_time"] )