from pathlib import Path
from sklearn.cluster import KMeans
import pandas as pd
from HelperFunctions.GetData import *
from HelperFunctions.StructureData import *
from HelperFunctions.StructureData import *
from HelperFunctions.ClusterLabelling import labelCluster
from NetFlow.Kmeans.MakeDataSet import makeDataSetKmeansNetFlow
from sklearn.metrics import confusion_matrix, f1_score, accuracy_score, recall_score, precision_score

'''
    Do K-means clustering on entropy and field data and write clusters to file
    Input:  
            testingSet: pandas dataframe, data set to detect on
            systemId:   string, name of the system to collect and calculate on
            interval:   timedelta object, size of the sliding window which the calculation is made on
            attackDate: string, date of the attack the calculations are made on
'''
def kmeansCombinedCalculation(silkFile, start, stop, clusterFrequency, frequency, systemId, interval, attackDate):
    p = Path('Calculations')
    q = p / 'Kmeans' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    
    ipP = Path('IPCalculations')
    ipPath = ipP / 'Kmeans'
    if not ipPath.exists():
        ipPath.mkdir(parents=True, exist_ok=False)
    
    dataPath = Path('NetFlow')
    dp = dataPath / 'Kmeans' / 'DataSets'
    if not dp.exists():
        dp.mkdir(parents=True)
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')

    entropyFile = str(dp) +"/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy"
    if Path(entropyFile).exists():
        with open(str(entropyFile), 'rb') as f:
            entropy_df = np.load(f, allow_pickle=True)
    else:
        print("Cant find", entropyFile)
        entropy_df = getDataNetFlow(silkFile, startTime, stopTime)

        if not dp.exists():
            dp.mkdir(parents=True, exist_ok=False)
        with open(str(dp) + "/Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".npy", 'wb') as f:
            np.save(f, entropy_df)
    
    f0IP = open(str(ipPath) + "/Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f0IP.write("sTime,eTime,srcIP,dstIP,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,nextHopIP,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets,packet_size_entropy,packet_size_entropy_rate,number_of_packets,number_of_bytes,real_label")
        
    intervalTime = (stopTime - startTime).total_seconds()/clusterFrequency.total_seconds()
    
    #Loop for every minute in a week
    for i in range(math.ceil(intervalTime)):
        stopTime = startTime + clusterFrequency
        

        testingSet = makeDataSetKmeansNetFlow(silkFile, start, stop, systemId, entropy_df, frequency, interval, attackDate)
        if len(testingSet) < 3:
            startTime += clusterFrequency
            continue
        sTime, eTime, measurements = structureData(testingSet)
        label = measurements[:,-1]
        measurements = measurements[:, :-1]

        sTime = pd.to_datetime(sTime)
        eTime = pd.to_datetime(eTime)

        prediction = KMeans(n_clusters=2, random_state=0, n_init="auto").fit_predict(measurements)
        attackCluster, db, cd0, cd1, counter0, counter1 = labelCluster(measurements, prediction, 0.5, 0, 0)
        if attackCluster == 0:
            nonAttackClusterDiameter = cd1
            attackClusterDiameter = cd0
        elif attackCluster == 1:
            nonAttackClusterDiameter = cd0
            attackClusterDiameter = cd1
        attackType = ""
        #If it is a burst attack and non attack cluster is empty
        if db < 0.5 and nonAttackClusterDiameter == 0:
            attackType = "Same"
        #If there is no burst and attack cluster is less compact than normal traffic
        elif db > 0.5 and attackClusterDiameter > (nonAttackClusterDiameter + 0):
            attackType = "Different"
        #If there is burst traffic and normal traffic and normal traffic is less compact than attack traffic
        elif db < 0.5 and nonAttackClusterDiameter > (attackClusterDiameter + 0):
            attackType = "Same"
        for i in range(len(prediction)):
            #line = "\n"  + sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ") + "," + eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ")
            lineIPs = "\n"  + sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ") + "," + eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ")
            for j in range(len(measurements[i])):
                lineIPs += "," + str(measurements[i][j])
            lineIPs +="," + attackType + "," +str(label[i])
            #line += "," +str(label[i])
            
            if prediction[i] == attackCluster:
                #f0.write(line)
                f0IP.write(lineIPs)
                
        startTime += clusterFrequency
    f0IP.close()
