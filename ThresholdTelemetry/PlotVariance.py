import json
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
import matplotlib.dates as mdates

def plotVariance(systemId, if_name, field):
    json_file_mean_var = open("ThresholdTelemetry/Thresholds/"+ str(systemId) + "." + str(if_name).replace("/","-") + "." + str(field)+".json", "r")
    json_object_mean_var = json.load(json_file_mean_var)
    json_file_mean_var.close()

    meanArray = []
    timeArray = []
    varianceArray = []
    for weekday in range(7):
        for hour in range(24):
            for minute in range(60):
                meanArray.append(json_object_mean_var["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]['mean'])
                varianceArray.append(json_object_mean_var["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]['variance'])
                timeArray.append(datetime.strptime("2023-01-" + f'{(1+weekday):02}' + " " + f'{hour:02}' + ":" + f'{minute:02}', '%Y-%m-%d %H:%M'))
    
    fig, ax = plt.subplots(1, 1, figsize=(20, 5))
    ax.plot(timeArray, meanArray)
    ax.set_xlabel('Time')
    ax.set_ylabel('Mean value of packets/s')
    ax.xaxis.set(
        major_locator=mdates.DayLocator(),
        major_formatter=mdates.DateFormatter("\n\n%A"),
        minor_locator=mdates.HourLocator((0, 12)),
        minor_formatter=mdates.DateFormatter("%H"),
    )
    fig.tight_layout()
    fig.savefig("ThresholdTelemetry/Plots/Mean--"+ str(systemId) + "." + str(if_name).replace("/","-") + "." + str(field)+".png")

    fig2, ax2 = plt.subplots(1, 1, figsize=(20, 5))
    ax2.plot(timeArray, varianceArray)
    ax2.set_xlabel('Time')
    ax2.set_ylabel('Standard deviation of packets/s')
    ax2.xaxis.set(
        major_locator=mdates.DayLocator(),
        major_formatter=mdates.DateFormatter("\n\n%A"),
        minor_locator=mdates.HourLocator((0, 12)),
        minor_formatter=mdates.DateFormatter("%H"),
    )
    fig2.tight_layout()
    fig2.savefig("ThresholdTelemetry/Plots/Variance--"+ str(systemId) + "." + str(if_name).replace("/","-") + "." + str(field)+".png")

plotVariance("trd-gw", "xe-0/1/0", "egress_stats__if_1sec_pkts")
