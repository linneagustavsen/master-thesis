import pandas as pd
from influxdb_client import InfluxDBClient
import numpy as np
from FFTDenoiser import fft_denoiser
import json
import statistics

json_file = open("DataFramesThresholdTelemetry/Schemas/RawValuesSchema.json", "r")
json_object_raw = json.load(json_file)
json_file.close()


#Set up a connection with the database
client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

query_api = client.query_api()

#Query to get all outgoing packet/sec rates from one link
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
for weekday in range(7):
    for hour in range(24):
        for minute in range(60):
            mean.append(np.mean(json_object_raw["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]))
            time.append(str(weekday) + " " + str(hour) + ":" + str(minute))

#De-nosing the weeks combined
denoisedMean = fft_denoiser(mean, 50)

threshold = pd.DataFrame({'_time': pd.Series(dtype='string'),
                   'mean': pd.Series(dtype='float'),
                   'variance': pd.Series(dtype='float')})
             

for weekday in range(7):
    for hour in range(24):
        for minute in range(60):
            mean_this_minute = denoisedMean[time.index(str(weekday) + " " + str(hour) + ":" + str(minute))]
            variance_this_minute = statistics.variance(json_object_raw["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)],xbar = mean_this_minute)
            new_row = pd.Series({'_time': str(weekday) + ' ' + str(hour) + ':' + str(minute),
                    'mean': mean_this_minute,
                   'variance': variance_this_minute})
            threshold = pd.concat([threshold, new_row.to_frame().T], ignore_index=True)

threshold.to_pickle("DataFramesThresholdTelemetry/DataFrames/ThresholdTrained3weeksOneTimeColumn.pkl")


