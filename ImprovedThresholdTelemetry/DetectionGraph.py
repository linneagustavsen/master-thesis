from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
import pandas as pd
import numpy as np
from datetime import timezone
import numpy as np
import matplotlib.pyplot as plt

#Open pickle file with threshold values
df = pd.read_pickle("ImprovedThresholdTelemetry/DataFrames/ThresholdTrained3weeks.pkl")

#Set up a connection with the database
client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

query_api = client.query_api()

#Query to get all outgoing packet/sec rates from one link in the period of detection
query = 'import "date" from(bucket: "skogul/1mnd")\
        |> range(start: 2022-10-13T00:00:00Z, stop: 2022-10-20T00:00:00Z)\
        |> filter(fn: (r) => r["systemId"] == "trd-gw")\
        |> filter(fn: (r) => r["if_name"] == "xe-0/1/0")\
        |> filter(fn: (r) => r["_field"] == "egress_stats__if_1sec_pkts")\
        |> group()        \
        |> keep(columns: ["_value", "_time"])'


#Make a flux table list from the output of the query
tables = query_api.query(query=query)

#Loop through all the tables and the rows and check their deviation from the threshold values
#Alert detection system if the deviation is higher than a predetermined value
deviationArray = []
valueArray = []
timeArray = []
meanArray = []
for table in tables:
    for row in table.records:
        mean_row = df.loc[(df['weekday'] == int(row.values["_time"].strftime('%w'))) & (df['hour'] == int(row.values["_time"].hour)) & (df['minute'] == int(row.values["_time"].minute))]['mean'].values[0]
        variance_row = df.loc[(df['weekday'] == int(row.values["_time"].strftime('%w'))) & (df['hour'] == int(row.values["_time"].hour)) & (df['minute'] == int(row.values["_time"].minute))]['variance'].values[0]
        deviation = (row.values["_value"]- mean_row)/variance_row

        meanArray.append(mean_row)
        deviationArray.append(deviation)
        valueArray.append(row.values["_value"])
        timeArray.append(str(row.values["_time"].strftime('%w')) + ' ' + str(row.values["_time"].hour) + ':' + str(row.values["_time"].minute))
        
fig, ax = plt.subplots(1, 1, figsize=(20, 5))
ax.set_xlabel('Time')
ax.set_ylabel('Packets/s')
plt.tight_layout()
ax.legend()
ax.plot(timeArray, meanArray, label = 'Mean')
fig.savefig("ImprovedThresholdTelemetry/Plots/Mean.png")

fig2, ax2 = plt.subplots(1, 1, figsize=(20, 5))
ax2.set_xlabel('Time')
ax2.set_ylabel('Packets/s')
plt.tight_layout()
ax2.legend()
ax2.plot(timeArray, deviationArray, label = 'Deviation')
fig2.savefig("ImprovedThresholdTelemetry/Plots/Deviation.png")

fig3, ax3 = plt.subplots(1, 1, figsize=(20, 5))
ax3.set_xlabel('Time')
ax3.set_ylabel('Packets/s')
plt.tight_layout()
ax3.legend()
ax3.plot(timeArray, valueArray, label = 'Actual traffic')
fig3.savefig("ImprovedThresholdTelemetry/Plots/TS.png")



'''
TODO: Skjekk tidsforskjellen på å bruke json og dataframes

'''