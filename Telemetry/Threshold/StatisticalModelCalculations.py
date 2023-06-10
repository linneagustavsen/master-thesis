from datetime import datetime,timedelta
import json
from pathlib import Path
from HelperFunctions.GetData import *
from HelperFunctions.IsAttack import isAttack
import paho.mqtt.client as mqtt
from time import sleep
from random import randrange

from HelperFunctions.Normalization import normalization
from HelperFunctionsTelemetry.GetDataTelemetry import getData
from Telemetry.Threshold.FindMaxVar import findMaxVar

'''
    Calculates deviation score of a traffic measurement and alerts in case of an anomaly
    Input:  
            systemId:   string, name of the system to collect and calculate on,
            if_name:    string, interface name,
            field:      string, what field to detect on
            start:      string, indicates the start time of the testing period
            stop:       string, indicates the stop time of the testing period
            threshold:  int, threshold for when to alert
            attackDate: string, date of the attack to detect
'''
def statisticalModelCalculations(start, stop, systemId, bucket, field, attackDate):
    p = Path('Calculations')
    r = p / 'Threshold' / 'Telemetry'
    if not r.exists():
        r.mkdir(parents=True)
    s = Path('Telemetry')
    q = s / 'Threshold' / 'Thresholds'
    if not q.exists():
        q.mkdir(parents=True)
    #Open json file with threshold values
    thresholdFile = str(q) + "/"+str(systemId)+ "." + str(field)+".json"
    if not Path(thresholdFile).exists():
       return
    json_file_mean_var = open(str(q) + "/"+str(systemId)+ "." + str(field)+".json", "r")
    json_object_mean_var = json.load(json_file_mean_var)
    json_file_mean_var.close()

    f = open(str(r) + "/" + str(field)+".attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f.write("sTime,eTime,Deviation_score,Value,Mean,Variance,real_label")
    fMax = open(str(r) + "/MaxVar." + str(field)+".attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    fMax.write("sTime,eTime,Deviation_score,Value,Mean,Variance,real_label")
    maxVar = findMaxVar(json_object_mean_var)
    
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')

    df = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),bucket, systemId,  [field])

    #Loop through all the tables and the rows and check their deviation from the threshold values
    #Alert detection system if the deviation is higher than a predetermined value
    for time, value in df.values:
        mean_row = json_object_mean_var["weekday"][time.strftime('%w')]["hour"][str(time.hour)]["minute"][str(time.minute)]["mean"]
        variance_row = json_object_mean_var["weekday"][time.strftime('%w')]["hour"][str(time.hour)]["minute"][str(time.minute)]["variance"]
        
        deviation = (value- mean_row)/variance_row

        deviationMaxVar = (value- mean_row)/maxVar

        attack = int(isAttack(time.replace(tzinfo=None)-timedelta(seconds = 2), time.replace(tzinfo=None)))
        
        line = "\n" + (time- timedelta(seconds = 2)).strftime("%Y-%m-%dT%H:%M:%SZ") + "," + time.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(deviation) + "," +str(value) + ","+str(mean_row) + "," +str(variance_row) + "," +str(attack)
        f.write(line)
        lineMax = "\n" + (time- timedelta(seconds = 2)).strftime("%Y-%m-%dT%H:%M:%SZ") + "," + time.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(deviationMaxVar) + "," +str(value) + ","+str(mean_row) + "," +str(maxVar) + "," +str(attack)
        fMax.write(lineMax)


        
    f.close()
    fMax.close()