from pathlib import Path
from sklearn.cluster import KMeans
from sklearn.metrics import confusion_matrix, f1_score, accuracy_score, recall_score, precision_score
import pandas as pd
from HelperFunctionsTelemetry.GetDataTelemetry import *
from HelperFunctions.StructureData import *
from datetime import datetime,timedelta
from HelperFunctions.IsAttack import *
from Telemetry.Kmeans.ClusterLabelling import labelCluster
import json
import paho.mqtt.client as mqtt
from time import sleep
from random import randrange

'''
    Do K-means clustering on field data write both clusters to file
    Input:  start:      string, indicating the start time of the data to detect on
            stop:       string, indicating the stop time of the data to detect on
            systemId:   string, name of the system to collect and calculate on  
            if_name:    string, interface name 
            fields:     list of strings, features to incorporate in the clustering
            attackDate: string, date of the attack the calculations are made on
'''
def calculationsKmeansFieldsTelemetry(start, stop, systemId, bucket, clusterFrequency, fields, attackDate):
    p = Path('Calculations')
    q = p / 'Kmeans' / 'Telemetry'
    if not q.exists():
        q.mkdir(parents=True)
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    intervalTime = (stopTime - startTime).total_seconds()/clusterFrequency.total_seconds()


    for i in range(math.ceil(intervalTime)):
        stopTime = startTime + clusterFrequency
        if systemId != "hoytek-gw2" and systemId != "narvik-gw4":
            cluster0 = open(str(q) + "/Fields.Cluster0.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".csv", "a")
            cluster0.write("sTime,eTime,egress_queue_info__0__cur_buffer_occupancy,egress_stats__if_1sec_pkts,egress_stats__if_1sec_octets,ingress_stats__if_1sec_pkts,ingress_stats__if_1sec_octets,real_label")
            
            cluster1 = open(str(q) + "/Fields.Cluster1.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".csv", "a")
            cluster1.write("sTime,eTime,egress_queue_info__0__cur_buffer_occupancy,egress_stats__if_1sec_pkts,egress_stats__if_1sec_octets,ingress_stats__if_1sec_pkts,ingress_stats__if_1sec_octets,real_label")
        else:
            cluster0 = open(str(q) + "/Fields.Cluster0.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".csv", "a")
            cluster0.write("sTime,eTime,egress_stats__if_1sec_pkts,egress_stats__if_1sec_octets,ingress_stats__if_1sec_pkts,ingress_stats__if_1sec_octets,real_label")
            cluster1 = open(str(q) + "/Fields.Cluster1.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".csv", "a")
            cluster1.write("sTime,eTime,egress_stats__if_1sec_pkts,egress_stats__if_1sec_octets,ingress_stats__if_1sec_pkts,ingress_stats__if_1sec_octets,real_label")
        
        cluster = open(str(q) + "/ClusterLabelling.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".csv", "a")
        cluster.write("AttackCluster,Davies-bouldin-score,ClusterDiameter0,ClusterDiameter1,ClusterSize0,ClusterSize1")
        f_scores = open(str(q) + "/Scores.Fields.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".csv", "a")
        f_scores.write("TP,FP,FN,TN")
        truePositives = 0
        falsePositives = 0
        falseNegatives = 0
        trueNegatives = 0

        dataPath = Path('Telemetry')
        dp = dataPath /'Kmeans'/ 'DataSets' 

        fieldsFile = str(dp) +"/Fields.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".pkl"
        if Path(fieldsFile).exists():
            with open(str(fieldsFile), 'rb') as f:
                df = pd.read_pickle(f)
        else:
            print("Cant find", fieldsFile)
            df = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), bucket, systemId, fields)
            if not dp.exists():
                dp.mkdir(parents=True, exist_ok=False)
            with open(str(dp) + "/Fields.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".pkl", 'wb') as f:
                df.to_pickle(f)

        if len(df) <2:
            startTime += clusterFrequency
            continue
        
        timeStamps, measurements = structureDataTelemetry(df)
        
        prediction = KMeans(n_clusters=2, random_state=0, n_init="auto").fit_predict(measurements)
        attackCluster, db, cd0, cd1, counter0, counter1 = labelCluster(measurements, prediction, 0.5, 0, 0)
        cluster.write("\n"+ str(attackCluster) + "," + str(db) + "," + str(cd0) + "," + str(cd1)+ "," + str(counter0)+ "," + str(counter1))

        labels = []
        for j in range(len(prediction)):
            attack = isAttack(timeStamps[j] -timedelta(seconds = 2), timeStamps[j])
            labels.append(attack)
            line = "\n"  + (timeStamps[j] - timedelta(seconds = 2)).strftime("%Y-%m-%dT%H:%M:%SZ") +","+ timeStamps[j].strftime("%Y-%m-%dT%H:%M:%SZ")
            for field in fields:
                if (systemId == "hoytek-gw2" or systemId == "narvik-gw4") and field == "egress_queue_info__0__cur_buffer_occupancy":
                    continue
                line += "," + str(df[field][j])
            line += "," +str(int(attack))

            if prediction[j] == 0: 
                cluster0.write(line)
                if attackCluster == 0:
                    if attack:
                        truePositives += 1
                    else:
                        falsePositives += 1
                else:
                    if attack:
                        falseNegatives += 1
                    else:
                        trueNegatives += 1
            elif prediction[j] == 1:
                cluster1.write(line)
                if attackCluster == 1:
                    if attack:
                        truePositives += 1
                    else:
                        falsePositives += 1
                else:
                    if attack:
                        falseNegatives += 1
                    else:
                        trueNegatives += 1

            
        f_scores.write("\n"+str(truePositives) + "," + str(falsePositives) + "," + str(falseNegatives) + "," + str(trueNegatives))
        f_scores.close()
        cluster0.close()
        cluster1.close()
        cluster.close()
        startTime += clusterFrequency
