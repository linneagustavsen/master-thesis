import statistics
import pandas as pd
from influxdb_client import InfluxDBClient
import numpy as np
import matplotlib.pyplot as plt
from FFTDenoiser import *
import warnings 
from influxdb_client.client.warnings import MissingPivotFunction

warnings.simplefilter("ignore", MissingPivotFunction)

#Set up a connection with the database
client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

query_api = client.query_api()

#All weeks: 2022-09-22T00:00:00Z, stop: 2022-10-21T00:00:00Z

query = '''from(bucket: "skogul/1mnd")
        |> range(start: 2022-09-29T00:00:00Z, stop: 2022-10-06T00:00:00Z)
        |> filter(fn: (r) => r["systemId"] == "trd-gw")
        |> filter(fn: (r) => r["if_name"] == "xe-0/1/0")
        |> filter(fn: (r) => r["_field"] == "egress_stats__if_1sec_pkts")
        |> group()
        |> aggregateWindow(every: 1m, fn: mean, createEmpty: false)         
        |> keep(columns: ["_value", "_time"])'''
    

df = query_api.query_data_frame(query=query)
df = df.drop(columns=['result', 'table'])

df.to_pickle("GraphThresholdTelemetry/DataFrames/Week2.pkl")

'''
denoised = fft_denoiser(df['_value'].to_numpy(), 0.00000000005)
print(type(denoised))
'''
'''fig, ax = plt.subplots(1, 1, figsize=(20, 5))'''
'''plt.plot("_time", "_value",data=df, label="Normal")
plt.plot(df["_time"].to_numpy(), denoised, label="Denoised")
ax.set_xlabel('Time')
ax.set_ylabel('Packets/s')
plt.legend()
plt.show()
'''
'''
    Thursday: check out that fourier thing on the website and replicate it.
    Plot the denoised signals and look at the difference.
    
    '''
