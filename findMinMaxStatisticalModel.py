from datetime import datetime,timedelta
import json
from pathlib import Path
from HelperFunctions.GetData import *
from HelperFunctionsTelemetry.GetDataTelemetry import getData, getDataTables
from Telemetry.Threshold.FindGoodThresholdStatisticalModel import findGoodThresholdStatisticalModel
from Telemetry.Threshold.FindMaxVar import findMaxVar
from findMaxMinEntropy import findMinMaxEntropyTelemetry

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

    deviations = []
    maxVarDeviations = []

    maxVar = findMaxVar(json_object_mean_var)

    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    intervalTime = (stopTime - startTime).days

    for i in range(math.ceil(intervalTime)):
        stopTime = startTime + timedelta(days = 1)

        df = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),"mars", systemId,  [field])
        startTime = stopTime
        #Loop through all the tables and the rows and check their deviation from the threshold values
        #Alert detection system if the deviation is higher than a predetermined value
        for time, value in df.values:
            mean_row = json_object_mean_var["weekday"][time.strftime('%w')]["hour"][str(time.hour)]["minute"][str(time.minute)]["mean"]
            variance_row = json_object_mean_var["weekday"][time.strftime('%w')]["hour"][str(time.hour)]["minute"][str(time.minute)]["variance"]
            
            deviation = (value- mean_row)/variance_row

            deviationVar = (value- mean_row)/maxVar

            deviations.append(deviation)
            maxVarDeviations.append(deviationVar)

    json_file = open("Telemetry/Threshold/Calculations/MinMaxValues/MinMax.StatisticalModel." + str(field)+".json", "w")
    json.dump({"minimum": min(deviations), "maximum": 3*np.nanmean(deviations)},json_file)
    json_file.close()
    json_file = open("Telemetry/Threshold/Calculations/MinMaxValues/MinMax.StatisticalModel_MaxVar." + str(field)+".json", "w")
    json.dump({"minimum": min(maxVarDeviations), "maximum": 3*np.nanmean(maxVarDeviations)},json_file)
    json_file.close()

start = "2023-02-23 00:00:00"
stop = "2023-03-07 00:00:00"
systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]
fields= ["egress_queue_info__0__cur_buffer_occupancy","egress_stats__if_1sec_pkts"]
systemId = "oslo-gw1"

for field in fields:
    print(field)
    findMinMaxStatisticalModel(systemId, field, start, stop)

frequency = timedelta(minutes=1)
intervals = [timedelta(minutes=5), timedelta(minutes=10), timedelta(minutes=15)]
for interval in intervals:
    findMinMaxEntropyTelemetry(start, stop, systemId, interval, frequency)

systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]
attackDate="08.03.23"
y_fields= ["egress_stats__if_1sec_octets", "ingress_stats__if_1sec_pkts", "ingress_stats__if_1sec_octets", "MaxVar.egress_queue_info__0__cur_buffer_occupancy", "MaxVar.egress_stats__if_1sec_pkts", "MaxVar.egress_stats__if_1sec_octets", "MaxVar.ingress_stats__if_1sec_pkts", "MaxVar.ingress_stats__if_1sec_octets"]

for y_field in y_fields:
    print(y_field)
    if y_field =="egress_stats__if_1sec_octets":
        for systemId in ["ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", "oslo-gw1"]:
            findGoodThresholdStatisticalModel(y_field, systemId, attackDate)
    else:
        for systemId in systems:
            print(systemId) 
            findGoodThresholdStatisticalModel(y_field, systemId, attackDate)
