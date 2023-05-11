from pathlib import Path
from sklearn.cluster import KMeans
from sklearn.metrics import confusion_matrix, f1_score, accuracy_score, recall_score, precision_score
import pandas as pd
from HelperFunctions.GetData import *
from HelperFunctions.StructureData import *
from datetime import datetime,timedelta
from HelperFunctions.IsAttack import *
from HelperFunctionsTelemetry.GetDataTelemetry import getEntropyData
from Telemetry.Kmeans.ClusterLabelling import labelCluster
from Telemetry.Kmeans.MakeDataSet import makeDataSetKmeansTelemetry

'''
    Do K-means clustering on entropy data and field data and write both clusters to file
    Input:  testingSet: pandas dataframe, data set to detect anomalies on
            systemId:   string, name of the system to collect and calculate on  
            if_name:    string, interface name
            interval:   timedelta object, size of the sliding window which the calculation is made on,
            attackDate: string, date of the attack the calculations are made on
'''
def calculationsKmeansCombinedTelemetry(start, stop, systemId, bucket, interval, frequency, clusterFrequency, fields, attackDate):
    p = Path('Calculations')
    q = p / 'Kmeans' / 'Telemetry'
    if not q.exists():
        q.mkdir(parents=True)
    dataPath = Path('Telemetry')
    dp = dataPath / 'Kmeans' / 'DataSets'
    if not dp.exists():
        dp.mkdir(parents=True)
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')

    entropyFile = str(dp) +"/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl"
    if Path(entropyFile).exists():
        with open(str(entropyFile), 'rb') as f:
            entropy_df = pd.read_pickle(f)
    else:
        print("Cant find", entropyFile)
        entropy_df = getEntropyData(startTime, stopTime, systemId, bucket, interval, frequency)

        if not dp.exists():
            dp.mkdir(parents=True, exist_ok=False)
        with open(str(dp) + "/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl", 'wb') as f:
            entropy_df.to_pickle(f)
    
    intervalTime = (stopTime - startTime).total_seconds()/clusterFrequency.total_seconds()
    for i in range(math.ceil(intervalTime)):
        stopTime = startTime + clusterFrequency
        f0 = open(str(q) + "/Combined.Cluster0."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".csv", "a")
        f0.write("sTime,eTime,egress_queue_info__0__cur_buffer_occupancy,egress_stats__if_1sec_pkt,ingress_stats__if_1sec_pkt,egress_stats__if_1sec_octet,ingress_stats__if_1sec_octet,entropy_packet_size,entropy_rate_packet_size,real_label")
        f1 = open(str(q) + "/Combined.Cluster1."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".csv", "a")
        f1.write("sTime,eTime,egress_queue_info__0__cur_buffer_occupancy,egress_stats__if_1sec_pkt,ingress_stats__if_1sec_pkt,egress_stats__if_1sec_octet,ingress_stats__if_1sec_octet,entropy_packet_size,entropy_rate_packet_size,real_label")

        cluster = open(str(q) + "/Combined.ClusterLabelling."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".csv", "a")
        cluster.write("AttackCluster,Davies-bouldin-score,ClusterDiameter0,ClusterDiameter1,ClusterSize0,ClusterSize1")
        '''f_scores = open(str(q) + "/Entropy.Score."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".csv", "a")
        f_scores.write("confusion_matrix,accuracy,f1,recall,precision")'''

        testingSet =  makeDataSetKmeansTelemetry(startTime, stopTime, entropy_df, systemId, bucket, fields, attackDate)
        if len(testingSet) == 0:
            startTime += clusterFrequency
            continue
        measurements = testingSet.values
        timeStamps = pd.read_pickle(str(dp) +"/Fields.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".pkl")["_time"].to_numpy()

        prediction = KMeans(n_clusters=2, random_state=0, n_init="auto").fit_predict(measurements)
        attackCluster, db, cd0, cd1, counter0, counter1 = labelCluster(measurements, prediction, 0.5, 0, 0)
        cluster.write("\n"+ str(attackCluster) + "," + str(db) + "," + str(cd0) + "," + str(cd1)+ "," + str(counter0)+ "," + str(counter1))
        labels = []
        for j in range(len(prediction)):
            attack = isAttack(timeStamps[j] -timedelta(seconds = 2), timeStamps[j])
            labels.append(attack)
            line = "\n"  + (timeStamps[j] -timedelta(seconds = 2)).strftime("%Y-%m-%dT%H:%M:%SZ") +"," + timeStamps[j].strftime("%Y-%m-%dT%H:%M:%SZ")
            for measurement in measurements[i]:
                line += "," + str(measurement)
            line += "," +str(int(attack))

            if prediction[i] == 0: 
                f0.write(line)
            elif prediction[i] == 1: 
                f1.write(line)

        
        f0.close()
        f1.close()
        cluster.close()
        ''' f_scores.write("\n"+str(confusion_matrix(labels, kmeans.labels_)) + ","+ str(accuracy_score(labels, kmeans.labels_)) + ","+ 
                str(f1_score(labels,kmeans.labels_)) + ","+ str(recall_score(labels,kmeans.labels_)) + ","+ 
                str(precision_score(labels,kmeans.labels_)))
        f_scores.close()'''
        startTime += clusterFrequency