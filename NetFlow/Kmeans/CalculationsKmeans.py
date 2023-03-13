import pickle
import pandas as pd
from GetData import *
from datetime import datetime
from silk import *
from StructureData import *

def detection(silkFile, systemId):
    f0 = open("NetFlow/Kmeans/Data/Cluster0."+ str(systemId) + ".csv", "a")
    f1 = open("NetFlow/Kmeans/Data/Cluster1."+ str(systemId) + ".csv", "a")
    f0.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration")
    f1.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration")
    
    '''infile = silkfile_open(silkFile, READ)
    
    testingData= getDataTesting(infile)
    testingData.to_pickle("NetFlow/Kmeans/RawData/RawTestingData.pkl")'''
    testingData = pd.read_pickle("NetFlow/Kmeans/RawData/RawTestingData.pkl")
    sTime, eTime, measurements = structureData(testingData)
    kmeans = pickle.load(open("NetFlow/Kmeans/Models/MLmodel.pkl", 'rb'))
    prediction = kmeans.predict(measurements)

    count0 = 0 
    count1 = 0
    for i in range(len(prediction)):
        if prediction[i] == 0:
            f0.write("\n"  + str(sTime[i]) + "," + str(eTime[i]) + "," +str(measurements[i][2])+ "," +str(measurements[i][3])+"," +str(measurements[i][4])+ "," +str(measurements[i][5])+ "," +str(measurements[i][6])+ "," +str(measurements[i][7])+ "," +str(measurements[i][8]) + "," +str(measurements[i][9])+ "," +str(measurements[i][10])+ "," +str(measurements[i][11])+ "," +str(measurements[i][12])+ "," +str(measurements[i][13])+ "," +str(measurements[i][14])+ "," +str(measurements[i][15]))
            count0 +=1
        elif prediction[i] == 1:
            f1.write("\n"  + str(sTime[i]) + "," + str(eTime[i]) + "," +str(measurements[i][2])+ "," +str(measurements[i][3])+"," +str(measurements[i][4])+ "," +str(measurements[i][5])+ "," +str(measurements[i][6])+ "," +str(measurements[i][7])+ "," +str(measurements[i][8]) + "," +str(measurements[i][9])+ "," +str(measurements[i][10])+ "," +str(measurements[i][11])+ "," +str(measurements[i][12])+ "," +str(measurements[i][13])+ "," +str(measurements[i][14])+ "," +str(measurements[i][15]))
            count1 += 1
    print(count0)
    print(count1)
    
    f0.close()
    f1.close()


systemId = "oslo-gw"
silkFile ="/home/linneafg/silk-data/RawDataFromFilter/two-hours-2011-01-02_10-11-sorted.rw"

detection(silkFile, systemId)