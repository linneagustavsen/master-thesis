from pathlib import Path
from sklearn.cluster import KMeans
from HelperFunctions.GetData import *
from silk import *
from HelperFunctions.StructureData import *
from NetFlow.Kmeans.ClusterLabelling import labelCluster

'''
    Do K-means clustering on fields and write clusters to file
    Input:  
            silkFile:   string, file with flow records sorted on time
            start:      string, indicating the start time of the data wanted
            stop:       string, indicating the stop time of the data wanted
            systemId:   string, name of the system to collect and calculate on
            attackDate: string, date of the attack the calculations are made on
'''
def kmeansCalculation(silkFile, start, stop, frequency, systemId, attackDate):
    p = Path('Calculations')
    q = p / 'Kmeans' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)

    #Makes datetime objects of the input times
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    intervalTime = (stopTime - startTime).total_seconds()/frequency.total_seconds()
 
    #Loop for every minute in a week
    for i in range(math.ceil(intervalTime)):
        stopTime = startTime + frequency
        f0 = open(str(q) + "/Cluster0.attack."+str(attackDate)+ ".stopTime."+str(stopTime)+ "."+str(systemId)+ ".csv", "a")
        f1 = open(str(q) + "/Cluster1.attack."+str(attackDate)+ ".stopTime"+str(stopTime)+ "."+str(systemId)+ ".csv", "a")
        f0.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,real_label")
        f1.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,real_label")
        cluster = open(str(q) + "/ClusterLabelling.attack."+str(attackDate)+ ".stopTime"+str(stopTime)+ "."+str(systemId)+ ".csv", "a")
        cluster.write("AttackCluster,Davies-bouldin-score,ClusterDiameter0,ClusterDiameter1,ClusterSize0,ClusterSize1")

        testingData = getDataNetFlow(silkFile, startTime, stopTime)
        sTime, eTime, measurements = structureDataNumpyArrays(testingData)
        
        label = measurements[:,-1]
        measurements = measurements[:, :-1]
        
        sTime = pd.to_datetime(sTime)
        eTime = pd.to_datetime(eTime)
        prediction = KMeans(n_clusters=2, random_state=0, n_init="auto").fit_predict(measurements)
        attackCluster, db, cd0, cd1, counter0, counter1 = labelCluster(measurements, prediction, 0.5, 0, 0)
        cluster.write("\n"+ str(attackCluster) + "," + str(db) + "," + str(cd0) + "," + str(cd1)+ "," + str(counter0)+ "," + str(counter1))

        count0 = 0 
        count1 = 0
    
        for i in range(len(prediction)):
            line = "\n"  + sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ") + "," + eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ")
            for j in range(len(measurements[i])):
                #Skip the IP fields
                if j == 0 or j == 1 or j == 16:
                    continue
                line += "," + str(measurements[i][j])
            line += "," +str(label[i])
            
            if prediction[i] == 0:
                f0.write(line)
                count0 +=1
            elif prediction[i] == 1:
                f1.write(line)
                count1 += 1
                
        f0.close()
        f1.close()

        startTime += frequency