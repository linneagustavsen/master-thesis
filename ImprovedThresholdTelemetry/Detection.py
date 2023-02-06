from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
import pandas as pd
import numpy as np
from datetime import timezone
import numpy as np
import matplotlib.pyplot as plt
import time
start_time = time.time()


#Open pickle file with threshold values
df = pd.read_pickle("ImprovedThresholdTelemetry/DataFrames/ThresholdTrained3weeksOneTimeColumn.pkl")
print(df.head(100))
#Set up a connection with the database
client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

query_api = client.query_api()

#Query to get all outgoing packet/sec rates from one link in the period of detection
query = 'from(bucket: "skogul/1mnd")\
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

print("Deviation score, Time, Value, Mean , Variance")
for table in tables:
    for row in table.records:
        thresholdRow = df.loc[(df['_time'] == str(row.values["_time"].strftime('%w')) + ' ' + str(row.values["_time"].hour) + ':' + str(row.values["_time"].minute))]
        mean_row = thresholdRow['mean'].values[0]
        variance_row = thresholdRow['variance'].values[0]
        deviation = (row.values["_value"] - mean_row)/variance_row

        if deviation > 0.002:
                #print("Deviation score of:", deviation, "at time:", row.values["_time"],"the value was:", row.values["_value"], "the mean is:", mean_row, "the variance is:", variance_row)
                print(deviation, ",", row.values["_time"],",", row.values["_value"], ",", mean_row, ",", variance_row)

print("--- %s seconds ---" % (time.time() - start_time))

'''
TODO: Skjekk tidsforskjellen på å bruke json og dataframes

'''