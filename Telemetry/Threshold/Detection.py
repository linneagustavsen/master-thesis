from datetime import datetime
import json
from HelperFunctions.GetData import *

'''
    Calculates deviation score of a traffic measurement and alerts in case of an anomaly
    Input:  systemId:   string, name of the system to collect and calculate on,
            if_name:    string, interface name,
            field:      string, what field to detect on
            start:      string, indicates the start time of the testing period
            stop:       string, indicates the stop time of the testing period
            threshold:  int, threshold for when to alert
            attackDate: string, date of the attack to detect
'''
def detection(systemId, if_name, field, start, stop, threshold, attackDate):
    #Open json file with threshold values
    json_file_mean_var = open("Telemetry/Threshold/Thresholds/"+str(systemId)+ "." + str(field)+".json", "r")
    json_object_mean_var = json.load(json_file_mean_var)
    json_file_mean_var.close()
    f = open("Detections/Threshold/Telemetry/attack."+str(attackDate)+ "."+str(systemId)+ "." + str(field)+".csv", "a")

    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')

    tables = getDataTables(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),systemId, if_name, field)
    
    f.write("Time,Deviation_score,Value,Mean,Variance")
    #Loop through all the tables and the rows and check their deviation from the threshold values
    #Alert detection system if the deviation is higher than a predetermined value
    for table in tables:
        for row in table.records:
            mean_row = json_object_mean_var["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)]["mean"]
            variance_row = json_object_mean_var["weekday"][row.values["_time"].strftime('%w')]["hour"][str(row.values["_time"].hour)]["minute"][str(row.values["_time"].minute)]["variance"]
            
            deviation = (row.values["_value"]- mean_row)/variance_row

            if deviation > threshold:
                f.write("\n"  + str(row.values["_time"]) + "," + str(deviation) + "," +str( row.values["_value"]) + ","+str(mean_row) + "," +str( variance_row))
    f.close()

detection("trd-gw", "xe-0/1/0", "egress_stats__if_1sec_pkts" ,"2022-09-21 01:00:00", "2022-09-22 00:00:00", 5)
#detection("trd-gw", "xe-0/1/0", "egress_stats__if_1sec_octets", "2022-10-13 00:00:00", "2022-10-20 00:00:00")
'''detection("trd-gw", "xe-0/1/0", "ingress_stats__if_1sec_pkts", "2022-10-13 00:00:00", "2022-10-20 00:00:00")
detection("trd-gw", "et-11/0/0", "ingress_stats__if_1sec_pkts", "2022-10-13 00:00:00", "2022-10-20 00:00:00")
detection("trd-gw", "et-11/0/0", "egress_stats__if_1sec_pkts", "2022-10-13 00:00:00", "2022-10-20 00:00:00")
detection("hmg9-gw1", "et-0/1/4", "ingress_stats__if_1sec_pkts", "2022-10-13 00:00:00", "2022-10-20 00:00:00")
detection("hmg9-gw1", "et-0/1/4", "egress_stats__if_1sec_pkts", "2022-10-13 00:00:00", "2022-10-20 00:00:00")
detection("hovedbygget-gw", "et-11/0/2", "egress_stats__if_1sec_pkts", "2022-10-13 00:00:00", "2022-10-20 00:00:00")
detection("hovedbygget-gw", "et-11/0/2", "ingress_stats__if_1sec_pkts", "2022-10-13 00:00:00", "2022-10-20 00:00:00")'''