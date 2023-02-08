from influxdb_client import InfluxDBClient
from influxdb_client.client.write_api import SYNCHRONOUS
import json
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
import matplotlib.dates as mdates
from scipy.stats import norm


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
            |> range(start: 2022-10-15T00:00:00Z, stop: 2022-10-20T00:00:00Z)\
            |> filter(fn: (r) => r["systemId"] == "' + systemId + '")\
            |> filter(fn: (r) => r["if_name"] == "' + if_name + '")\
            |> filter(fn: (r) => r["_field"] == "' + field + '")\
            |> group()        \
            |> keep(columns: ["_value", "_time"])'

    #Make a flux table list from the output of the query
    tables = query_api.query(query=query)
    
    #Loop through all the tables and the rows and check their deviation from the threshold values
    #Alert detection system if the deviation is higher than a predetermined value

    for table in tables:
        for row in table.records:
            mean_row = json_object_mean_var["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)]["mean"]
            variance_row = json_object_mean_var["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)]["variance"]
            deviation = (row.values["_value"]- mean_row)/variance_row

            if deviation > 17:
                fig, ax = plt.subplots(1, 1, figsize=(20, 5))
                x = np.linspace(0, row.values["_value"]+100000, 1000)
                ax.plot(x, norm.pdf(x, mean_row, variance_row), label="Normal distribution")
                ax.scatter([row.values["_value"]], [norm(mean_row, variance_row).pdf(row.values["_value"])], color="red", label="Deviation")
                ax.annotate(str(norm(mean_row, variance_row).pdf(row.values["_value"])), xy=(row.values["_value"], norm(mean_row, variance_row).pdf(row.values["_value"])))
                ax.text(0.7, 0.9, 'Deviation score: ' + str(deviation), horizontalalignment='center', verticalalignment='center', transform=ax.transAxes, bbox=dict(facecolor='blue', alpha=0.2))
                ax.set_xlabel('Packets/s')
                ax.set_ylabel('Probability density')
                fig.legend()
                fig.tight_layout()
                fig.savefig("ThresholdTelemetry/Plots/DeviationProbability/"+ row.values["_time"].strftime("%d-%m-%Y--%H:%M:%S") + "--"+ str(systemId) + "." + str(if_name).replace("/","-") + "." + str(field)+".png")

detection("trd-gw", "xe-0/1/0", "egress_stats__if_1sec_pkts")