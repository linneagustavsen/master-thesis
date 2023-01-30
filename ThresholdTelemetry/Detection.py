from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
import json
import numpy as np
from datetime import timezone

#Open json file with threshold values
json_file_mean_var = open("ThresholdTelemetry/RawValues/MeanVarValuesDeNoised.json", "r")
json_object_mean_var = json.load(json_file_mean_var)
json_file_mean_var.close()

#Set up a conncetion with the database
client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

query_api = client.query_api()

#Query to get all outgoing packet/sec rates from one link in the period of detection
query = 'import "date" from(bucket: "skogul/1mnd")\
        |> range(start: 2022-10-17T00:00:00Z, stop: 2022-10-21T01:00:00Z)\
        |> filter(fn: (r) => r["link_name"] == "alta-narvik")\
        |> filter(fn: (r) => r["_field"] == "egress_stats__if_1sec_pkts")\
        |> keep(columns: ["_value", "_time"])'

#Make a flux table list from the output of the query
tables = query_api.query(query=query)

#Loop through all the tables and the rows and check their deviation from the threshold values
#Alert detection system if the deviation is higher than a predetermined value
for table in tables:
    for row in table.records:
        mean_row = json_object_mean_var["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)]["mean"]
        variance_row = json_object_mean_var["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)]["variance"]
        D = (row.values["_value"]- mean_row)/variance_row

        if D > 0.05:
            print("Deviation score",D, "at", row.values["_time"] )