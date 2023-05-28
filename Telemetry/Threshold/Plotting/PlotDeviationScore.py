import json
import numpy as np
import matplotlib.pyplot as plt
from scipy.stats import norm

from HelperFunctionsTelemetry.GetDataTelemetry import getDataTables


def plotDeviationScore(systemId, field):
    #Open json file with threshold values
    json_file_mean_var = open("Telemetry/Threshold/Thresholds/"+ str(systemId) + "." + str(field)+".json", "r")
    json_object_mean_var = json.load(json_file_mean_var)
    json_file_mean_var.close()

    tables = getDataTables("2023-03-08T14:29:55Z", "2023-03-08T14:34:55Z", systemId, "april", field)
    #Loop through all the tables and the rows and check their deviation from the threshold values
    #Alert detection system if the deviation is higher than a predetermined value

    for table in tables:
        for row in table.records:
            mean_row = json_object_mean_var["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)]["mean"]
            variance_row = json_object_mean_var["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)]["variance"]
            deviation = (row.values["_value"]- mean_row)/variance_row

            if deviation >= 1:
                distributionThisMinute = norm(mean_row, variance_row)
                fig, ax = plt.subplots(1, 1, figsize=(20, 5))
                x = np.linspace(0, 2000000000)
                ax.plot(x, distributionThisMinute.png(x), label="Normal distribution")
                ax.scatter([row.values["_value"]], [distributionThisMinute.png(row.values["_value"])], color="red", label="Probability")
                ax.annotate(str(distributionThisMinute.png(row.values["_value"])), xy=(row.values["_value"], distributionThisMinute.png(row.values["_value"])))
                ax.text(0.7, 0.9, 'Deviation score: ' + str(deviation), horizontalalignment='center', verticalalignment='center', transform=ax.transAxes, bbox=dict(facecolor='blue', alpha=0.2))
                ax.set_xlabel('Bytes/s')
                ax.set_ylabel('Probability')
                fig.legend()
                fig.tight_layout()
                fig.savefig("Plots/Threshold/DeviationScore"+ row.values["_time"].strftime("%d-%m-%Y--%H:%M:%S") + "--"+ str(systemId) + str(field)+".png")
                plt.close(fig)
plotDeviationScore("bergen-gw3", "egress_stats__if_1sec_octets")