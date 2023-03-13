import pickle
import pandas as pd
from GetData import *
from StructureData import *

def detection(silkFile, start, stop, systemId, frequency, interval):
    f0 = open("NetFlow/Kmeans/Calculations/Entropy.Cluster0."+ str(systemId) + ".csv", "a")
    f1 = open("NetFlow/Kmeans/Calculations/Entropy.Cluster1."+ str(systemId) + ".csv", "a")
    f0.write("Time,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets")
    f1.write("Time,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets")

    df = getEntropyData(silkFile, start, stop, frequency, interval)
    df.to_pickle("NetFlow/Kmeans/RawData/TestingDataEntropy."+str(systemId)+ ".pkl")
    #df = pd.read_pickle("NetFlow/Kmeans/RawData/TestingDataEntropy."+str(systemId)+ ".pkl")
    timeStamps, measurements = structureDataEntropy(df)
    kmeans = pickle.load(open("NetFlow/Kmeans/Models/MLmodelEntropy."+str(systemId)+ ".pkl", 'rb'))

    prediction = kmeans.predict(measurements)
    count0 = 0 
    count1 = 0
    for i in range(len(prediction)):
        if prediction[i] == 0:
            f0.write("\n"  + str(timeStamps[i]) + "," +str(measurements[i][0])+ "," +str(measurements[i][1]) + "," +str(measurements[i][2]) + "," +str(measurements[i][3]) + "," +str(measurements[i][4]) + "," +str(measurements[i][5]) + "," +str(measurements[i][6]) + "," +str(measurements[i][7]) + "," +str(measurements[i][8]))
            count0 +=1
        elif prediction[i] == 1:
            f1.write("\n" + str(timeStamps[i])+ "," +str(measurements[i][0])+ "," +str(measurements[i][1]) + "," +str(measurements[i][2]) + "," +str(measurements[i][3]) + "," +str(measurements[i][4]) + "," +str(measurements[i][5]) + "," +str(measurements[i][6]) + "," +str(measurements[i][7]) + "," +str(measurements[i][8]))
            count1 += 1
    print(count0)
    print(count1)
    
    f0.close()
    f1.close()


systemId = "oslo-gw"
silkFile ="/home/linneafg/silk-data/RawDataFromFilter/two-hours-2011-01-02_10-11-sorted.rw"
start = "2011-01-02 10:00:00"
stop = "2011-01-02 12:00:00"
frequency = timedelta(minutes=1)
interval = timedelta(minutes=5)

detection(silkFile, start, stop, systemId, frequency, interval)