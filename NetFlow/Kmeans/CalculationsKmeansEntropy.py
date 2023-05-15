from pathlib import Path
from sklearn.cluster import KMeans
from HelperFunctions.GetData import *
from HelperFunctions.IsAttack import isAttack
from HelperFunctions.StructureData import *
from NetFlow.Kmeans.ClusterLabelling import labelCluster
from sklearn.metrics import confusion_matrix, f1_score, accuracy_score, recall_score, precision_score

'''
    Do K-means clustering on entropy data and write clusters to file
    Input:  silkFile:   string, file with flow records sorted on time
            start:      string, indicating the start time of the data wanted
            stop:       string, indicating the stop time of the data wanted
            systemId:   string, name of the system to collect and calculate on
            frequency:  timedelta object, frequency of metric calculation
            interval:   timedelta object, size of the sliding window which the calculation is made on
            attackDate: string, date of the attack the calculations are made on
'''
def kmeansEntropyCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate):
    p = Path('Calculations')
    q = p / 'Kmeans' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    f0 = open(str(q) + "/Entropy.Cluster0."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f1 = open(str(q) + "/Entropy.Cluster1."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f0.write("sTime,eTime,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets,packet_size_entropy,packet_size_entropy_rate,number_of_packets,number_of_bytes,real_label")
    f1.write("sTime,eTime,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets,packet_size_entropy,packet_size_entropy_rate,number_of_packets,number_of_bytes,real_label")
    cluster = open(str(q) + "/Entropy.ClusterLabelling."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    cluster.write("AttackCluster,Davies-bouldin-score,ClusterDiameter0,ClusterDiameter1,ClusterSize0,ClusterSize1")
    f_scores = open(str(q) + "/Scores.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f_scores.write("TP,FP,FN,TN")
    truePositives = 0
    falsePositives = 0
    falseNegatives = 0
    trueNegatives = 0
    
    dataPath = Path('NetFlow')
    dp = dataPath /'Kmeans'/ 'DataSets' 

    entropyFile = str(dp) +"/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl"
    if Path(entropyFile).exists():
        with open(str(entropyFile), 'rb') as f:
            df = pd.read_pickle(f)
    else:
        print("Cant find", entropyFile)
        df = getEntropyDataNetFlow(silkFile, start, stop, frequency, interval)
        
        if not dp.exists():
            dp.mkdir(parents=True, exist_ok=False)
        with open(str(dp) + "/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl", 'wb') as f:
            df.to_pickle(f)

    if len(df) <2:
        return
    timeIntervals, measurements, labels = structureDataEntropyNumpyArrays(df)
    #timeStamps = pd.to_datetime(timeStamps)

    prediction = KMeans(n_clusters=2, random_state=0, n_init="auto").fit_predict(measurements)
    attackCluster, db, cd0, cd1, counter0, counter1 = labelCluster(measurements, prediction, 0.5, 0, 0)
    cluster.write("\n"+ str(attackCluster) + "," + str(db) + "," + str(cd0) + "," + str(cd1)+ "," + str(counter0)+ "," + str(counter1))
    
    for i in range(len(prediction)):
        line = "\n"  + timeIntervals[i].left.strftime("%Y-%m-%dT%H:%M:%SZ") + "," + timeIntervals[i].right.strftime("%Y-%m-%dT%H:%M:%SZ")
        for measurement in measurements[i]:
            line += "," + str(measurement)
        line += "," +str(int(labels[i]))
        
        if prediction[i] == attackCluster:
            f0.write(line)
            if labels[i] == 1:
                truePositives += 1
            else:
                falsePositives += 1
        elif prediction[i] != attackCluster:
            f1.write(line)
            if labels[i] == 1:
                falseNegatives += 1
            else:
                trueNegatives += 1
    
    f0.close()
    f1.close()
    '''f_scores.write("\n"+str(confusion_matrix(labels, prediction)) + ","+ str(accuracy_score(labels, prediction)) + ","+ 
                   str(f1_score(labels,prediction)) + ","+ str(recall_score(labels,prediction)) + ","+ 
                   str(precision_score(labels,prediction)))'''
    f_scores.write("\n"+str(truePositives) + "," + str(falsePositives) + "," + str(falseNegatives) + "," + str(trueNegatives))
    f_scores.close()