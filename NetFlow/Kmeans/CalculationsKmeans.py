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
 
    #Loop for every minute in a week
    for i in range(math.ceil(intervalTime)):
        stopTime = startTime + clusterFrequency
        f0 = open(str(q) + "/Fields.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".csv", "a")
        #f1 = open(str(q) + "/Cluster1.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".csv", "a")
        f0.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,real_label")
        #f1.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,real_label")
        '''f0IP = open(str(ipPath) + "/Cluster0.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".csv", "a")
        f1IP = open(str(ipPath) + "/Cluster1.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".csv", "a")
        f0IP.write("sTime,eTime,srcIP,dstIP,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,nextHopIP,real_label")
        f1IP.write("sTime,eTime,srcIP,dstIP,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,nextHopIP,real_label")'''
        f_scores = open(str(q) + "/Scores.Fields.attack."+str(attackDate)+ ".stopTime."+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".csv", "a")
        f_scores.write("TP,FP,FN,TN")
        truePositives = 0
        falsePositives = 0
        falseNegatives = 0
        trueNegatives = 0
        
        cluster = open(str(q) + "/ClusterLabelling.attack."+str(attackDate)+ ".stopTime"+stopTime.strftime("%H.%M.%S")+ "."+str(systemId)+ ".csv", "a")
        cluster.write("AttackCluster,Davies-bouldin-score,ClusterDiameter0,ClusterDiameter1,ClusterSize0,ClusterSize1")
        
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
        cluster.write("\n"+ str(attackCluster) + "," + str(db) + "," + str(cd0) + "," + str(cd1)+ "," + str(counter0)+ "," + str(counter1))

        for i in range(len(prediction)):
            line = "\n"  + sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ") + "," + eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ")
            #lineIPs = "\n"  + sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ") + "," + eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ")
            for j in range(len(measurements[i])):
                #lineIPs += "," + str(measurements[i][j])
                #Skip the IP fields
                if j == 0 or j == 1 or j == 16:
                    continue
                line += "," + str(measurements[i][j])
            #lineIPs += "," +str(label[i])
            line += "," +str(label[i])
            
            if prediction[i] == attackCluster:
                f0.write(line)
                #f0IP.write(lineIPs)
                if label[i] == 1:
                    truePositives += 1
                else:
                    falsePositives += 1

            elif prediction[i] != attackCluster:
                if label[i] == 1:
                    falseNegatives += 1
                else:
                    trueNegatives += 1
                #f1.write(line)
                #f1IP.write(lineIPs)

                
        f0.close()
        '''f1.close()
        f0IP.close()
        f1IP.close()'''
        cluster.close()
        f_scores.write("\n"+str(truePositives) + "," + str(falsePositives) + "," + str(falseNegatives) + "," + str(trueNegatives))
        '''f_scores.write("\n"+str(confusion_matrix(label, prediction)) + ","+ str(accuracy_score(label, prediction)) + ","+ 
                   str(f1_score(label,prediction)) + ","+ str(recall_score(label,prediction)) + ","+ 
                   str(precision_score(label,prediction)))'''
        f_scores.close()
        startTime += clusterFrequency