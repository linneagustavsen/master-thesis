from sklearn.cluster import KMeans
from HelperFunctions.GetData import *
from silk import *
from HelperFunctions.StructureData import *
from HelperFunctions.IsAttack import *

'''
    Do K-means clustering on field and write clusters to file
    Input:  silkFile:   string, File with flow records sorted on time
            start:      string, indicating the start time of the data wanted
            stop:       string, indicating the stop time of the data wanted
            systemId:   string, name of the system to collect and calculate on
            attackDate: string, date of the attack the calculations are made on
'''
def kmeansCalculation(silkFile, start, stop, systemId, attackDate):
    f0 = open("Calculations/Kmeans/NetFlow/Cluster0.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f1 = open("Calculations/Kmeans/NetFlow/Cluster1.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f0.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,real_label")
    f1.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,real_label")
    
    testingData = getDataNetFlow(silkFile, start, stop)
    #testingData.to_pickle("NetFlow/Kmeans/RawData/TestingData.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    #testingData = pd.read_pickle("NetFlow/Kmeans/RawData/TestingData.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    sTime, eTime, measurements = structureData(testingData)
    measurements = measurements[:, :-1]
    label = measurements[:,-1]
    sTime = pd.to_datetime(sTime)
    eTime = pd.to_datetime(eTime)
    prediction = KMeans(n_clusters=2, random_state=0, n_init="auto").fit_predict(measurements)

    count0 = 0 
    count1 = 0
    for i in range(len(prediction)):
        line = "\n"  + sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ") + "," + eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ")
        for j in range(len(measurements[i])):
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