import statistics
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
import json
from FFTDenoiser import *
import numpy as np

json_file = open("/home/linneafg/Code/master-thesis/ThresholdTelemetry/RawValuesSchema.json", "r")
json_file_mean_var = open("/home/linneafg/Code/master-thesis/ThresholdTelemetry/MeanVarSchema.json", "r")
json_object_raw = json.load(json_file)
json_object_mean_var = json.load(json_file_mean_var)
json_file.close()
json_file_mean_var.close()

client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

query_api = client.query_api()


query = 'import "date" from(bucket: "skogul/1mnd")\
        |> range(start: 2022-09-21T02:00:00Z, stop: 2022-10-07T07:00:00Z)\
        |> filter(fn: (r) => r["link_name"] == "alta-narvik")\
        |> filter(fn: (r) => r["_field"] == "egress_stats__if_1sec_pkts")\
        |> keep(columns: ["_value", "_time"])'
        #if i dont want to de-noise it I can just do |> mean()
tables = query_api.query(query=query)
for table in tables:
    print(table)
    for row in table.records:
        json_object_raw["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)].append(row.values["_value"])
print("Raw values finished!")
for weekday in range(7):
    for hour in range(24):
        for minute in range(60):
            #json_object_mean_var["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]["mean"] = np.mean(json_object_raw["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)])
            json_object_mean_var["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]["mean"] = np.mean(fft_denoiser(json_object_raw["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)], 50))
            json_object_mean_var["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]["variance"] = statistics.variance(json_object_raw["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)],xbar = json_object_mean_var["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]["mean"])
        print("Weekday:", weekday, "Hour:", hour, "finished!!")
           
json_file_mean_var = open("MeanVarValuesDeNoised.json", "w")
json.dump(json_object_mean_var,json_file_mean_var)
json_file_mean_var.close()