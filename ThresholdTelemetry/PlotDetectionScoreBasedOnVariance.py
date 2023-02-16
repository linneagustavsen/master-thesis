from influxdb_client import InfluxDBClient
from influxdb_client.client.write_api import SYNCHRONOUS
import json
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
import matplotlib.dates as mdates

#Set up a connection with the database
client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

def detection(systemId, if_name, field):
    #Open json file with threshold values
    json_file_mean_var = open("ThresholdTelemetry/Thresholds/"+ str(systemId) + "." + str(if_name).replace("/","-") + "." + str(field)+".json", "r")
    json_object_mean_var = json.load(json_file_mean_var)
    json_file_mean_var.close()

    query_api = client.query_api()

    #Query to get all outgoing packet/sec rates from one link in the period of detection
    query = 'from(bucket: "skogul/1mnd")\
            |> range(start: 2022-10-13T00:00:00Z, stop: 2022-10-20T00:00:00Z)\
            |> filter(fn: (r) => r["systemId"] == "' + systemId + '")\
            |> filter(fn: (r) => r["if_name"] == "' + if_name + '")\
            |> filter(fn: (r) => r["_field"] == "' + field + '")\
            |> group()        \
            |> keep(columns: ["_value", "_time"])'

    #Make a flux table list from the output of the query
    tables = query_api.query(query=query)
    
    #Loop through all the tables and the rows and check their deviation from the threshold values
    #Alert detection system if the deviation is higher than a predetermined value
    deviationArray = []
    timeArray = []
    deviationMaxArray = []
    varianceArray = []
    for weekday in range(7):
        for hour in range(24):
            for minute in range(60):
                varianceArray.append(json_object_mean_var["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]['variance'])
                
    maxVariance = np.amax(varianceArray)

    for table in tables:
        for row in table.records:
            mean_row = json_object_mean_var["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)]["mean"]
            variance_row = json_object_mean_var["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)]["variance"]
            timeArray.append(row.values["_time"])
            deviation = (row.values["_value"]- mean_row)/variance_row
            deviationMax = (row.values["_value"]- mean_row)/maxVariance

            deviationArray.append(deviation)
            deviationMaxArray.append(deviationMax)
  
    fig, ax = plt.subplots(1, 1, figsize=(20, 5))
    ax.plot(timeArray, deviationArray)
    
    ax.xaxis.set(
        major_locator=mdates.DayLocator(),
        major_formatter=mdates.DateFormatter("\n\n%A\n"),
        minor_locator=mdates.HourLocator((0, 12)),
        minor_formatter=mdates.DateFormatter("%H"),
    )
    ax.set_xlabel('Time')
    ax.set_ylabel('Deviation score')
    fig.tight_layout()
    fig.savefig("ThresholdTelemetry/Plots/Deviation--"+ str(systemId) + "." + str(if_name).replace("/","-") + "." + str(field)+".png")

    fig2, ax2 = plt.subplots(1, 1, figsize=(20, 5))
    ax2.plot(timeArray, deviationMaxArray)
    ax2.xaxis.set(
        major_locator=mdates.DayLocator(),
        major_formatter=mdates.DateFormatter("\n\n%A\n"),
        minor_locator=mdates.HourLocator((0, 12)),
        minor_formatter=mdates.DateFormatter("%H"),
    )
    ax2.set_xlabel('Time')
    ax2.set_ylabel('Deviation score')
    fig2.tight_layout()
    fig2.savefig("ThresholdTelemetry/Plots/DeviationUsingMaxVariance--"+ str(systemId) + "." + str(if_name).replace("/","-") + "." + str(field)+".png")

detection("trd-gw", "xe-0/1/0", "egress_stats__if_1sec_pkts")