import statistics
from influxdb_client import InfluxDBClient
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

#Set up a connection with the database
client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

query_api = client.query_api()

query = 'from(bucket: "skogul/1mnd")\
        |> range(start: 2022-09-22T00:00:00Z, stop: 2022-10-13T00:00:00Z)\
        |> filter(fn: (r) => r["systemId"] == "trd-gw")\
        |> filter(fn: (r) => r["if_name"] == "xe-0/1/0")\
        |> filter(fn: (r) => r["_field"] == "egress_stats__if_1sec_pkts")\
        |> group()        \
        |> keep(columns: ["_value", "_time"])'

#Make a flux table list from the output of the query
tables = query_api.query(query=query)

#Loop through all the tables and the rows and store them in a json structure based on weekday, hour, and minute
for table in tables:
    for row in table.records:
        json_object_raw["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)].append(row.values["_value"])

mean = []
time = []
#Loop through all the minutes for each hour for each weekday and calculate the mean
for weekday in range(7):
    for hour in range(24):
        for minute in range(60):
            mean.append(np.mean(json_object_raw["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]))
            time.append(str(weekday) + " " + str(hour) + ":" + str(minute))
            

#De-nosing the weeks combined
denoisedMean = fft_denoiser(mean, 50)

#store the denoised mean and variance for all the minutes for each hour for each weekday in a json structure
for weekday in range(7):
    for hour in range(24):
        for minute in range(60):
            mean_this_minute = denoisedMean[time.index(str(weekday) + " " + str(hour) + ":" + str(minute))]
            variance_this_minute = statistics.variance(json_object_raw["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)],xbar = mean_this_minute)
            json_object_mean_var["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]["mean"] = mean_this_minute
            json_object_mean_var["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]["variance"] = variance_this_minute

#Write the mean and variance values to a json file      
json_file_mean_var = open("ThresholdTelemetry/Thresholds/MeanVarValuesDenoisedNTNU.json", "w")
json.dump(json_object_mean_var,json_file_mean_var)
json_file_mean_var.close()