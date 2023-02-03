import pandas as pd
from influxdb_client import InfluxDBClient
import numpy as np
import matplotlib.pyplot as plt
import warnings 
from influxdb_client.client.warnings import MissingPivotFunction
from FFTDenoiser import fft_denoiser
import datetime

warnings.simplefilter("ignore", MissingPivotFunction)


#Set up a connection with the database
client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

query_api = client.query_api()

#All weeks: 2022-09-22T00:00:00Z, stop: 2022-10-21T00:00:00Z
weeks = ["start: 2022-09-22T00:00:00Z, stop: 2022-09-29T00:00:00Z", "start: 2022-09-29T00:00:00Z, stop: 2022-10-06T00:00:00Z", "start: 2022-10-06T00:00:00Z, stop: 2022-10-13T00:00:00Z", "start: 2022-10-13T00:00:00Z, stop: 2022-10-20T00:00:00Z"]
''''
for w in weeks:
    #Query to get all outgoing packet/sec rates from one link
    query = 'from(bucket: "skogul/1mnd")\
    |> range(' + w + ')\
    |> filter(fn: (r) => r["systemId"] == "trd-gw")\
    |> filter(fn: (r) => r["if_name"] == "xe-0/1/0")\
    |> filter(fn: (r) => r["_field"] == "egress_stats__if_1sec_pkts")\
    |> group()        \
    |> keep(columns: ["_value", "_time"])'


    df = query_api.query_data_frame(query=query)
    df = df.drop(columns=['result', 'table'])
    df.to_pickle("ImprovedThresholdTelemetry/DataFrames/Week" + str(weeks.index(w)+1)+".pkl")


timeArray = df['_time'].to_numpy()
denoisedValueArray = fft_denoiser(df["_value"].to_numpy(), 50)
if len(timeArray) > len(denoisedValueArray):
    timeArray = timeArray[:-(len(timeArray)-len(denoisedValueArray))]
elif len(timeArray) < len(denoisedValueArray):
    denoisedValueArray = denoisedValueArray[:-(len(denoisedValueArray)-len(timeArray))]

df_denoised = pd.DataFrame({'_time': timeArray, '_value': denoisedValueArray})

df_denoised['_time']= pd.to_datetime(df['_time'])
df.to_pickle("ImprovedThresholdTelemetry/DataFrames/Week" + str(weeks.index(w)+1)+"-denoised.pkl")

'''
'''
1. Go through all weeks and store them (maybe not aggregate)
2. Lay them on top of each other and take the mean for each minute
3. De-noise that distribution for the weeks combined
4. Store the denoised distribution
5. Calculate the variance based on the de-noised value that minute and all the raw data from that weekday and that minute for all the weeks
6. Store the variance for each minute
'''
raw_values_monday = pd.DataFrame({'_time': pd.Series(dtype='datetime64[ns]'),
                   '_value': pd.Series(dtype='np.float64')})
raw_values_tuesday = pd.DataFrame({'_time': pd.Series(dtype='datetime64[ns]'),
                   '_value': pd.Series(dtype='np.float64')})
raw_values_wednesday = pd.DataFrame({'_time': pd.Series(dtype='datetime64[ns]'),
                   '_value': pd.Series(dtype='np.float64')})
raw_values_thursday = pd.DataFrame({'_time': pd.Series(dtype='datetime64[ns]'),
                   '_value': pd.Series(dtype='np.float64')})
raw_values_friday = pd.DataFrame({'_time': pd.Series(dtype='datetime64[ns]'),
                   '_value': pd.Series(dtype='np.float64')})
raw_values_saturday = pd.DataFrame({'_time': pd.Series(dtype='datetime64[ns]'),
                   '_value': pd.Series(dtype='np.float64')})
raw_values_sunday = pd.DataFrame({'_time': pd.Series(dtype='datetime64[ns]'),
                   '_value': pd.Series(dtype='np.float64')})                

print(raw_values_friday.dtypes)
'''for i in range(1,len(weeks)+1):
    df = pd.read_pickle("ImprovedThresholdTelemetry/DataFrames/Week"+ str(i) +".pkl")
    print(df.dtypes)
'''
