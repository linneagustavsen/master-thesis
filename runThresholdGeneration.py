from datetime import datetime, timedelta
import json
import math
from pathlib import Path
import statistics

import numpy as np

from HelperFunctionsTelemetry.GetDataTelemetry import getDataTables
from Telemetry.Threshold.FFTDenoiser import fft_denoiser


def thresholdGeneration(systemId, field):
    p = Path('Telemetry')
    q = p / 'Threshold'
    s = q / 'Schemas'
    if not s.exists():
        s.mkdir(parents=True)
    #Open json schema files to make json objects from them
    json_file = open(str(s) + "/RawValuesSchema.json", "r")
    json_file_mean_var = open(str(s) + "/MeanVarSchema.json", "r")
    json_object_raw = json.load(json_file)
    json_object_mean_var = json.load(json_file_mean_var)
    json_file.close()
    json_file_mean_var.close()

    counter = 0
    start = ['2022-09-22 00:00:00', '2023-01-25 00:00:00']
    stop = ['2022-10-22 00:00:00', '2023-02-23 00:00:00']

    buckets = ["october", "february"]
    for bucket in buckets:
        print("started on bucket", bucket, "for system", systemId, "field:", field)
        startTime = datetime.strptime(start[counter], '%Y-%m-%d %H:%M:%S')
        stopTime = datetime.strptime(stop[counter], '%Y-%m-%d %H:%M:%S')
        intervalTime = (stopTime - startTime).total_seconds()/86400

        for i in range(math.ceil(intervalTime)):
            if i % 10 == 0:
                print("Iteration", i)

            stopTime = startTime + timedelta(days = 1)
            #Makes datetime objects of the input times
            tables = getDataTables(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),systemId, bucket, field)
            startTime = stopTime
            #Loop through all the tables and the rows and store them in a json structure based on weekday, hour, and minute
            for table in tables:
                for row in table.records:
                    json_object_raw["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)].append(row.values["_value"])
        counter += 1

    mean = []
    time = []
    #Loop through all the minutes for each hour for each weekday and calculate the mean
    for weekday in range(7):
        for hour in range(24):
            for minute in range(60):
                mean.append(np.mean(json_object_raw["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]))
                time.append(str(weekday) + " " + str(hour) + ":" + str(minute))
                

    #De-nosing the weeks combined
    denoisedMean = fft_denoiser(mean, 50)

    #Store the denoised mean and variance for all the minutes for each hour for each weekday in a json structure
    for weekday in range(7):
        for hour in range(24):
            for minute in range(60):
                if len(json_object_raw["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]) < 2:
                    json_object_mean_var["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]["mean"] = None
                    json_object_mean_var["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]["variance"] = None
                    print("\n This time didnt have enough: weekday", str(weekday), "hour", str(hour), "minute", str(minute))
                    print(json_object_raw["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)])
                    continue

                mean_this_minute = denoisedMean[time.index(str(weekday) + " " + str(hour) + ":" + str(minute))]
                variance_this_minute = statistics.stdev(json_object_raw["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)],xbar = mean_this_minute)
                json_object_mean_var["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]["mean"] = mean_this_minute
                json_object_mean_var["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]["variance"] = variance_this_minute

    t = q / 'Thresholds'
    if not t.exists():
        t.mkdir(parents=True)
    #Write the mean and variance values to a json file      
    json_file_mean_var = open(str(t) + "/"+str(systemId)+ "." + str(field)+".json", "w")
    json.dump(json_object_mean_var,json_file_mean_var)
    json_file_mean_var.close()

systems = ["trd-gw", "teknobyen-gw2", "teknobyen-gw1", "ifi2-gw5", 
           "tromso-gw5", "stangnes-gw", "rodbergvn-gw2", "narvik-kv-gw", "narvik-gw3", "tromso-fh-gw",
            "ma2-gw", "narvik-gw4"]
fields = ["egress_stats__if_1sec_octets","egress_stats__if_1sec_pkts", "ingress_stats__if_1sec_octets","ingress_stats__if_1sec_pkts"]


for system in systems:
    for field in fields:
        thresholdGeneration(system, field)
'''systemId = "oslo-gw1"
fields = ["egress_stats__if_1sec_octets","egress_stats__if_1sec_pkts", "ingress_stats__if_1sec_octets","ingress_stats__if_1sec_pkts"]
for field in fields:
    thresholdGeneration(systemId, field)'''