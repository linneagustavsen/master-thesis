from sklearn.cluster import KMeans
import pandas as pd
from HelperFunctions.GetData import *
from HelperFunctions.StructureData import *
from datetime import datetime,timedelta
from HelperFunctions.IsAttack import *

'''
    Do K-means clustering on field data write both clusters to file
    Input:  start:      string, indicating the start time of the data to detect on
            stop:       string, indicating the stop time of the data to detect on
            systemId:   string, name of the system to collect and calculate on  
            if_name:    string, interface name 
            fields:     list of strings, features to incorporate in the clustering
            attackDate: string, date of the attack the calculations are made on
'''
def detectionKmeansTelemetry(start, stop, systemId, if_name, fields, attackDate):
    f0 = open("Calculations/Kmeans/Telemetry/Cluster0.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f1 = open("Calculations/Kmeans/Telemetry/Cluster1.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f0.write("Time,egress_queue_info__0__avg_buffer_occupancy,egress_queue_info__0__cur_buffer_occupancy,egress_stats__if_1sec_pkt,egress_stats__if_1sec_octet,real_label")
    f1.write("Time,egress_queue_info__0__avg_buffer_occupancy,egress_queue_info__0__cur_buffer_occupancy,egress_stats__if_1sec_pkt,egress_stats__if_1sec_octet,real_label")

    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    df = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), systemId, if_name, fields)
    
    #df.to_pickle("NetFlow/Kmeans/RawData/Testing.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    #df = pd.read_pickle("NetFlow/Kmeans/RawData/Testing.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    timeStamps, measurements = structureDataTelemetry(df)
    
    prediction = KMeans(n_clusters=2, random_state=0, n_init="auto").fit_predict(measurements)
    count0 = 0 
    count1 = 0
    for i in range(len(prediction)):
        line = "\n"  + str(timeStamps[i])
        for measurement in measurements[i]:
            line += "," + str(measurement)
        #timestamp = datetime.strptime(timeStamps[i], ("%Y-%m-%dT%H:%M:%SZ"))
        line += "," +str(int(isAttack(timeStamps[i])))
        
        if prediction[i] == 0:
            f0.write(line)
            count0 +=1
        elif prediction[i] == 1:
            f1.write(line)
            count1 += 1
    print(count0)
    print(count1)
    
    f0.close()
    f1.close()

'''start = "2022-09-21 01:00:00"
stop = "2022-09-22 00:00:00"
systemId = "trd-gw"
if_name = "xe-0/1/0"
interval = timedelta(minutes = 5)
frequency = timedelta(minutes = 1)
attackDate = "21.09"
fields = ["egress_queue_info__0__avg_buffer_occupancy", "egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets"]

detectionKmeansTelemetry(start, stop, systemId, if_name, fields, attackDate)'''