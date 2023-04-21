from matplotlib.path import Path
from sklearn.cluster import KMeans
import pandas as pd
from HelperFunctions.GetData import *
from HelperFunctions.StructureData import *
from datetime import datetime,timedelta
from HelperFunctions.IsAttack import *

'''
    Do K-means clustering on entropy data and field data and write both clusters to file
    Input:  testingSet: pandas dataframe, data set to detect anomalies on
            systemId:   string, name of the system to collect and calculate on  
            if_name:    string, interface name
            interval:   timedelta object, size of the sliding window which the calculation is made on,
            attackDate: string, date of the attack the calculations are made on
'''
def detectionKmeansCombinedTelemetry(testingSet, systemId, if_name, attackDate):
    p = Path('Calculations')
    q = p / 'Kmeans' / 'Telemetry'
    if not q.exists():
        q.mkdir(parents=True)
    f0 = open(str(q) + "/Combined.Cluster0."+ str(systemId) + "." + str(if_name).replace("/","-")+ "." + str(attackDate) + ".csv", "a")
    f1 = open(str(q) + "/Combined.Cluster1."+ str(systemId) + "." + str(if_name).replace("/","-")+ "." + str(attackDate) + ".csv", "a")
    f0.write("Time,egress_queue_info__0__avg_buffer_occupancy,egress_queue_info__0__cur_buffer_occupancy,egress_stats__if_1sec_pkt,egress_stats__if_1sec_octet,entropy_packet_size,entropy_rate_packet_size,real_label")
    f1.write("Time,egress_queue_info__0__avg_buffer_occupancy,egress_queue_info__0__cur_buffer_occupancy,egress_stats__if_1sec_pkt,egress_stats__if_1sec_octet,entropy_packet_size,entropy_rate_packet_size,real_label")

    p = Path('Telemetry')
    q = p / 'Kmeans' / 'RawData'
    if not q.exists():
        q.mkdir(parents=True)
    #df = pd.read_pickle(str(q) +"TestingSetCombined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    measurements = testingSet.values
    timeStamps = pd.read_pickle(str(q) +"/Testing.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")["_time"].to_numpy()

    prediction = KMeans(n_clusters=2, random_state=0, n_init="auto").fit_predict(measurements)
    count0 = 0 
    count1 = 0
    for i in range(len(prediction)):
        line = "\n"  + timeStamps[i].strftime("%Y-%m-%dT%H:%M:%SZ")
        for measurement in measurements[i]:
            line += "," + str(measurement)
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
attackDate = "21.09"
fields = ["egress_queue_info__0__avg_buffer_occupancy", "egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets"]

detectionKmeansCombinedTelemetry(testingSet, systemId, if_name, attackDate)'''