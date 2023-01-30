import statistics
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
import json
from FFTDenoiser import *
import numpy as np


#Open json schema files to make json objects from them
json_file = open("ThresholdTelemetry/Schemas/RawValuesSchema.json", "r")
json_file_mean_var = open("ThresholdTelemetry/Schemas/MeanVarSchema.json", "r")
json_object_raw = json.load(json_file)
json_object_mean_var = json.load(json_file_mean_var)
json_file.close()
json_file_mean_var.close()

#Set up a conncetion with the database
client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

query_api = client.query_api()

#NB NB Use systemID and interface name rather than link_name because it doesnt exist 7-10 october
''' Will be like this instead 
  |> filter(fn: (r) => r["systemId"] == "dora-gw")
  |> filter(fn: (r) => r["if_name"] == "ge-1/1/0")
  |> filter(fn: (r) => r["_field"] == "egress_stats__if_1sec_pkts")'''

#Query to get all outgoing packet/sec rates from one link
query = 'import "date" from(bucket: "skogul/1mnd")\
        |> range(start: 2022-09-21T02:00:00Z, stop: 2022-10-07T07:00:00Z)\
        |> filter(fn: (r) => r["link_name"] == "alta-narvik")\
        |> filter(fn: (r) => r["_field"] == "egress_stats__if_1sec_pkts")\
        |> keep(columns: ["_value", "_time"])'

#Make a flux table list from the output of the query
tables = query_api.query(query=query)

#Loop through all the tables and the rows and store them in a json structure based on weekday, hour, and minute
for table in tables:
    for row in table.records:
        json_object_raw["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)].append(row.values["_value"])

#Loop through all the minutes for each hour for each weekday and calculate the mean and variance
for weekday in range(7):
    for hour in range(24):
        for minute in range(60):
            #json_object_mean_var["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]["mean"] = np.mean(json_object_raw["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)])
            json_object_mean_var["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]["mean"] = np.mean(fft_denoiser(json_object_raw["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)], 50))
            json_object_mean_var["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]["variance"] = statistics.variance(json_object_raw["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)],xbar = json_object_mean_var["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]["mean"])

#Write the mean and variance values to a json file      
json_file_mean_var = open("ThresholdTelemetry/RawValues/MeanVarValuesDeNoised.json", "w")
json.dump(json_object_mean_var,json_file_mean_var)
json_file_mean_var.close()