from pathlib import Path
import statistics
from HelperFunctions.GetData import *
import json
from .FFTDenoiser import *
import numpy as np
from datetime import datetime

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

'''
    Calculates and stores the deonised mean value and the standard deviation 
    of a traffic measure for each specific minute of each specific weekday
    Input:  systemId:   string, name of the system to collect and calculate on,
            if_name:    string, interface name,
            field:      string, what field to make a threshold for,
            start:      string, indicates the start time of the training period,
            stop:       string, indicates the stop time of the training period
'''

def thresholdGeneration(systemId, if_name, field, start, stop):
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')

    tables = getDataTables(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),systemId, if_name, field)

    #Loop through all the tables and the rows and store them in a json structure based on weekday, hour, and minute
    for table in tables:
        for row in table.records:
            json_object_raw["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)].append(row.values["_value"])

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

'''thresholdGeneration("trd-gw", "xe-0/1/0", "ingress_stats__if_1sec_pkts","2022-09-22 00:00:00" ,"2022-10-13 00:00:00")
thresholdGeneration("trd-gw", "et-11/0/0", "ingress_stats__if_1sec_pkts", "2022-09-22 00:00:00" ,"2022-10-13 00:00:00")
thresholdGeneration("trd-gw", "et-11/0/0", "egress_stats__if_1sec_pkts", "2022-09-22 00:00:00" ,"2022-10-13 00:00:00")
thresholdGeneration("hmg9-gw1", "et-0/1/4", "ingress_stats__if_1sec_pkts", "2022-09-22 00:00:00" ,"2022-10-13 00:00:00")
thresholdGeneration("hmg9-gw1", "et-0/1/4", "egress_stats__if_1sec_pkts", "2022-09-22 00:00:00" ,"2022-10-13 00:00:00")
thresholdGeneration("hovedbygget-gw", "et-11/0/2", "egress_stats__if_1sec_pkts", "2022-09-22 00:00:00" ,"2022-10-13 00:00:00")
thresholdGeneration("hovedbygget-gw", "et-11/0/2", "ingress_stats__if_1sec_pkts", "2022-09-22 00:00:00" ,"2022-10-13 00:00:00")
thresholdGeneration("trd-gw", "xe-0/1/0", "egress_stats__if_1sec_octets", "2022-09-22 00:00:00" ,"2022-10-13 00:00:00")'''

