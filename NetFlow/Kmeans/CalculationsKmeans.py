from pathlib import Path
from sklearn.cluster import KMeans
from HelperFunctions.GetData import *
from silk import *
from HelperFunctions.StructureData import *
from HelperFunctions.ClusterLabelling import labelCluster
from sklearn.metrics import confusion_matrix, f1_score, accuracy_score, recall_score, precision_score

'''
    Do K-means clustering on fields and write clusters to file
    Input:  
            silkFile:   string, file with flow records sorted on time
            start:      string, indicating the start time of the data wanted
            stop:       string, indicating the stop time of the data wanted
            systemId:   string, name of the system to collect and calculate on
            attackDate: string, date of the attack the calculations are made on
'''
def kmeansCalculation(silkFile, start, stop, clusterFrequency, systemId, attackDate):
    p = Path('Calculations')
    q = p / 'Kmeans' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)

    ipP = Path('IPCalculations')
    ipPath = ipP / 'Kmeans'
    if not ipPath.exists():
        ipPath.mkdir(parents=True, exist_ok=False)

    #Makes datetime objects of the input times
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    intervalTime = (stopTime - startTime).total_seconds()/clusterFrequency.total_seconds()
    f0IP = open(str(ipPath) + "/Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f0IP.write("sTime,eTime,srcIP,dstIP,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,nextHopIP,attackType,real_label")
    #Loop for every minute in a week
    for i in range(math.ceil(intervalTime)):
        stopTime = startTime + clusterFrequency

        dataPath = Path('NetFlow')
        dp = dataPath /'Kmeans'/ 'DataSets' 
        fieldsFile = str(dp) +"/Fields.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".npy"
        if Path(fieldsFile).exists():
            with open(str(fieldsFile), 'rb') as f:
                testingData = np.load(f, allow_pickle=True)
        else:
            print("Cant find", fieldsFile)
            testingData = getDataNetFlow(silkFile, startTime, stopTime)

            if not dp.exists():
                dp.mkdir(parents=True, exist_ok=False)
            with open(str(dp) + "/Fields.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".npy", 'wb') as f:
                np.save(f, testingData)

        if len(testingData) <3:
            startTime += clusterFrequency
            continue
        sTime, eTime, measurements, label = structureDataNumpyArrays(testingData)

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