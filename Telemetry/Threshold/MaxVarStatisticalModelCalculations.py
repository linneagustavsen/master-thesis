from datetime import datetime, timedelta
import json
from pathlib import Path
from HelperFunctions.GetData import *
from HelperFunctions.IsAttack import isAttack
from HelperFunctions.Normalization import normalization
from HelperFunctionsTelemetry.GetDataTelemetry import getDataTables
from .FindMaxVar import *
import paho.mqtt.client as mqtt

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
def calculationsMaxVar(start, stop, systemId, bucket, field, attackDate):
    p = Path('Calculations')
    r = p / 'Threshold' / 'Telemetry'
    if not r.exists():
        r.mkdir(parents=True)
    s = Path('Telemetry')
    q = s / 'Threshold' / 'Thresholds'
    if not q.exists():
        q.mkdir(parents=True)
    #Open json file with threshold values
    json_file_mean_var = open(str(q) + "/"+str(systemId)+ "." + str(field)+".json", "r")
    json_object_mean_var = json.load(json_file_mean_var)
    json_file_mean_var.close()
    f = open(str(r) + "/MaxVar." + str(field)+".attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f.write("sTime,eTime,Deviation_score,Value,Mean,Variance,real_label")

    maxVar = findMaxVar(json_object_mean_var)
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')

    tables = getDataTables(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),systemId, bucket, field)    
    #Loop through all the tables and the rows and check their deviation from the threshold values
    #Alert detection system if the deviation is higher than a predetermined value
    for table in tables:
        for row in table.records:
            mean_row = json_object_mean_var["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)]["mean"]
            
            deviation = (row.values["_value"]- mean_row)/maxVar

            attack = isAttack(row.values["_time"]-timedelta(seconds = 2), row.values["_time"])
        
            line = "\n" + (row.values["_time"]- timedelta(seconds = 2)).strftime("%Y-%m-%dT%H:%M:%SZ") + "," + row.values["_time"].strftime("%Y-%m-%dT%H:%M:%SZ") + "," + str(deviation) + "," +str(row.values["_value"]) + ","+str(mean_row) + "," +str(maxVar) + "," +str(attack)
            f.write(line)
    f.close()
