from datetime import datetime,timedelta
import json
from pathlib import Path
from HelperFunctions.GetData import *
from HelperFunctionsTelemetry.GetDataTelemetry import getDataTables
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
def findMinMaxStatisticalModel(systemId, field, start, stop):
    s = Path('Telemetry')
    q = s / 'Threshold' / 'Thresholds'
    if not q.exists():
        q.mkdir(parents=True)
    #Open json file with threshold values
    json_file_mean_var = open(str(q) + "/"+str(systemId)+ "." + str(field)+".json", "r")
    json_object_mean_var = json.load(json_file_mean_var)
    json_file_mean_var.close()

    maxNormal = 0
    minNormal = 1000000000000000000

    maxVarNormal = 0
    minVarNormal = 1000000000000000000

    maxVar = findMaxVar(json_object_mean_var)
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')

    tables = getDataTables(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),systemId, "mars", field)
    
    #Loop through all the tables and the rows and check their deviation from the threshold values
    #Alert detection system if the deviation is higher than a predetermined value
    for table in tables:
        for row in table.records:
            mean_row = json_object_mean_var["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)]["mean"]
            variance_row = json_object_mean_var["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)]["variance"]
            
            deviation = (row.values["_value"]- mean_row)/variance_row
            deviationVar = (row.values["_value"]- mean_row)/maxVar

            if deviation > maxNormal:
                maxNormal = deviation
            elif deviation < minNormal:
                minNormal = deviation 
            
            if deviationVar > maxVarNormal:
                maxVarNormal = deviationVar
            elif deviationVar < minVarNormal:
                minVarNormal = deviationVar 

    json_file = open("Telemetry/Threshold/Calculations/MinMax.StatisticalModel." + str(field)+".json", "w")
    json.dump({"minimum": minNormal, "maximum": maxNormal},json_file)
    json_file.close()
    json_file = open("Telemetry/Threshold/Calculations/MinMax.StatisticalModel_MaxVar." + str(field)+".json", "w")
    json.dump({"minimum": minVarNormal, "maximum": maxVarNormal},json_file)
    json_file.close()