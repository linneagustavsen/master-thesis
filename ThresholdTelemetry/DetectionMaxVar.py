from datetime import datetime
import json
from GetData import *
from FindMaxVar import *
'''
    Calculates deviation score of a traffic measurement and alerts in case of an anomaly
    Input:  system ID,
            interface name,
            field,
            start time as a string,
            stop time as a string
'''


def detection(systemId, if_name, field, start, stop):
    #Open json file with threshold values
    json_file_mean_var = open("ThresholdTelemetry/Thresholds/"+ str(systemId) + "." + str(if_name).replace("/","-") + "." + str(field)+".json", "r")
    json_object_mean_var = json.load(json_file_mean_var)
    
    json_file_mean_var.close()
    f = open("ThresholdTelemetry/Detections/"+ str(systemId) + "." + str(if_name).replace("/","-") + "." + str(field)+".MaxVar.txt", "a")

    maxVar = findMaxVar(json_object_mean_var)
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')

    tables = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),systemId, if_name, field)
    
    f.write("Time, Deviation score, Value, Mean, Variance")
    #Loop through all the tables and the rows and check their deviation from the threshold values
    #Alert detection system if the deviation is higher than a predetermined value
    for table in tables:
        for row in table.records:
            mean_row = json_object_mean_var["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)]["mean"]
            
            deviation = (row.values["_value"]- mean_row)/maxVar

            if deviation > 2:
                f.write("\n"  + str(row.values["_time"]) + "," + str(deviation) + "," +str( row.values["_value"]) + ","+str(mean_row) + "," +str( maxVar))
    f.close()

detection("trd-gw", "xe-0/1/0", "egress_stats__if_1sec_pkts" ,"2022-10-13 00:00:00", "2022-10-20 00:00:00")
detection("trd-gw", "xe-0/1/0", "egress_stats__if_1sec_octets", "2022-10-13 00:00:00", "2022-10-20 00:00:00")
'''detection("trd-gw", "xe-0/1/0", "ingress_stats__if_1sec_pkts", "2022-10-13 00:00:00", "2022-10-20 00:00:00")
detection("trd-gw", "et-11/0/0", "ingress_stats__if_1sec_pkts", "2022-10-13 00:00:00", "2022-10-20 00:00:00")
detection("trd-gw", "et-11/0/0", "egress_stats__if_1sec_pkts", "2022-10-13 00:00:00", "2022-10-20 00:00:00")
detection("hmg9-gw1", "et-0/1/4", "ingress_stats__if_1sec_pkts", "2022-10-13 00:00:00", "2022-10-20 00:00:00")
detection("hmg9-gw1", "et-0/1/4", "egress_stats__if_1sec_pkts", "2022-10-13 00:00:00", "2022-10-20 00:00:00")
detection("hovedbygget-gw", "et-11/0/2", "egress_stats__if_1sec_pkts", "2022-10-13 00:00:00", "2022-10-20 00:00:00")
detection("hovedbygget-gw", "et-11/0/2", "ingress_stats__if_1sec_pkts", "2022-10-13 00:00:00", "2022-10-20 00:00:00")'''