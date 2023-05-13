from datetime import datetime, timedelta
import json
import math
from pathlib import Path
import statistics

import numpy as np

from HelperFunctionsTelemetry.GetDataTelemetry import getDataTables
from Telemetry.Threshold.FFTDenoiser import fft_denoiser
from Telemetry.Threshold.StatisticalModelCalculations import statisticalModelCalculations


def thresholdGeneration(systemId, field):
    p = Path('Telemetry')
    q = p / 'Threshold'
    s = q / 'Schemas'
    if not s.exists():
        s.mkdir(parents=True)

    pathWeeklyPattern = q / 'Calculations' / 'WeeklyPattern'
    if not pathWeeklyPattern.exists():
        pathWeeklyPattern.mkdir(parents=True)
    #Open json schema files to make json objects from them
    json_file = open(str(s) + "/RawValuesSchema.json", "r")
    json_file_mean_var = open(str(s) + "/MeanVarSchema.json", "r")
    json_object_raw = json.load(json_file)
    json_object_mean_var = json.load(json_file_mean_var)
    json_file.close()
    json_file_mean_var.close()

    json_file_week1 = open(str(s) + "/RawValuesSchema.json", "r")
    json_object_week1 = json.load(json_file_week1)
    json_file_week1.close()
    json_file_week2 = open(str(s) + "/RawValuesSchema.json", "r")
    json_object_week2 = json.load(json_file_week2)
    json_file_week2.close()
    json_file_week3 = open(str(s) + "/RawValuesSchema.json", "r")
    json_object_week3 = json.load(json_file_week3)
    json_file_week3.close()
    json_file_week4 = open(str(s) + "/RawValuesSchema.json", "r")
    json_object_week4 = json.load(json_file_week4)
    json_file_week4.close()
    json_file_week5 = open(str(s) + "/RawValuesSchema.json", "r")
    json_object_week5 = json.load(json_file_week5)
    json_file_week5.close()
    json_file_week6 = open(str(s) + "/RawValuesSchema.json", "r")
    json_object_week6 = json.load(json_file_week6)
    json_file_week6.close()
    json_file_week7 = open(str(s) + "/RawValuesSchema.json", "r")
    json_object_week7 = json.load(json_file_week7)
    json_file_week7.close()
    json_file_week8 = open(str(s) + "/RawValuesSchema.json", "r")
    json_object_week8 = json.load(json_file_week8)
    json_file_week8.close()

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
                    if stopTime < datetime.strptime("2022-09-29 00:00:00", '%Y-%m-%d %H:%M:%S'):
                        json_object_week1["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)].append(row.values["_value"])
                    elif stopTime < datetime.strptime("2022-10-06 00:00:00", '%Y-%m-%d %H:%M:%S'):
                        json_file_week1 = open(str(pathWeeklyPattern) + "/Week1."+str(systemId)+ "." + str(field)+".json", "w")
                        json.dump(json_object_week1,json_file_week1)
                        json_file_week1.close()

                        json_object_week2["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)].append(row.values["_value"])
                    elif stopTime < datetime.strptime("2022-10-13 00:00:00", '%Y-%m-%d %H:%M:%S'):
                        json_file_week2 = open(str(pathWeeklyPattern) + "/Week2."+str(systemId)+ "." + str(field)+".json", "w")
                        json.dump(json_object_week2,json_file_week2)
                        json_file_week2.close()

                        json_object_week3["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)].append(row.values["_value"])
                    elif stopTime < datetime.strptime("2022-10-20 00:00:00", '%Y-%m-%d %H:%M:%S'):
                        json_file_week3 = open(str(pathWeeklyPattern) + "/Week3."+str(systemId)+ "." + str(field)+".json", "w")
                        json.dump(json_object_week3,json_file_week3)
                        json_file_week3.close()

                        json_object_week4["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)].append(row.values["_value"])
                    elif startTime > datetime.strptime("2023-01-26 00:00:00", '%Y-%m-%d %H:%M:%S') and stopTime < datetime.strptime("2023-02-02 00:00:00", '%Y-%m-%d %H:%M:%S'):
                        json_file_week4 = open(str(pathWeeklyPattern) + "/Week4."+str(systemId)+ "." + str(field)+".json", "w")
                        json.dump(json_object_week4,json_file_week4)
                        json_file_week4.close()

                        json_object_week5["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)].append(row.values["_value"])
                    elif stopTime < datetime.strptime("2023-01-09 00:00:00", '%Y-%m-%d %H:%M:%S'):
                        json_file_week5 = open(str(pathWeeklyPattern) + "/Week5."+str(systemId)+ "." + str(field)+".json", "w")
                        json.dump(json_object_week5,json_file_week5)
                        json_file_week5.close()

                        json_object_week6["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)].append(row.values["_value"])
                    elif stopTime < datetime.strptime("2023-01-16 00:00:00", '%Y-%m-%d %H:%M:%S'):
                        json_file_week6 = open(str(pathWeeklyPattern) + "/Week6."+str(systemId)+ "." + str(field)+".json", "w")
                        json.dump(json_object_week6,json_file_week6)
                        json_file_week6.close()

                        json_object_week7["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)].append(row.values["_value"])
                    elif stopTime < datetime.strptime("2023-01-23 00:00:00", '%Y-%m-%d %H:%M:%S'):
                        json_file_week7 = open(str(pathWeeklyPattern) + "/Week7."+str(systemId)+ "." + str(field)+".json", "w")
                        json.dump(json_object_week7,json_file_week7)
                        json_file_week7.close()

                        json_object_week8["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)].append(row.values["_value"])
                    
        counter += 1
    json_file_week8 = open(str(pathWeeklyPattern) + "/Week8."+str(systemId)+ "." + str(field)+".json", "w")
    json.dump(json_object_week8,json_file_week8)
    json_file_week8.close()

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

systems = ["hovedbygget-gw", "hoytek-gw2", "bergen-gw3",  "oslo-gw1"]
field = "egress_queue_info__0__cur_buffer_occupancy"

for systemId in systems:
    thresholdGeneration(systemId, field)
