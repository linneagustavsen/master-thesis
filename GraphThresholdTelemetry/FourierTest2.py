import statistics
import pandas as pd
from influxdb_client import InfluxDBClient
import numpy as np
import matplotlib.pyplot as plt
import warnings 
from influxdb_client.client.warnings import MissingPivotFunction
from FFTDenoiser import fft_denoiser

warnings.simplefilter("ignore", MissingPivotFunction)

df = pd.read_pickle("GraphThresholdTelemetry/DataFrames/all-weeks.pkl")

fig, ax = plt.subplots(1, 1, figsize=(20, 5))
'''
timeArray = df['_time'].to_numpy()
denoisedValueArray = fft_denoiser(df["_value"].to_numpy(), 50)

if len(timeArray) > len(denoisedValueArray):
    timeArray = timeArray[:-(len(timeArray)-len(denoisedValueArray))]
elif len(timeArray) < len(denoisedValueArray):
    timeArray = timeArray[:-(len(denoisedValueArray)-len(timeArray))]

ax.plot(timeArray, denoisedValueArray)
ax.set_xlabel('Time')
ax.set_ylabel('Packets/s')
plt.tight_layout()
plt.savefig("GraphThresholdTelemetry/Plots/all-weeks-denoised.png")
'''
ax.plot("_time", "_value", data=df)
ax.set_xlabel('Time')
ax.set_ylabel('Packets/s')
plt.tight_layout()
plt.savefig("GraphThresholdTelemetry/Plots/all-weeks.png")

