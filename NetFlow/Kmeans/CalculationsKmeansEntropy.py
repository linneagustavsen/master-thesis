from sklearn.cluster import KMeans
from .GetData import *
from HelperFunctions.StructureData import *

def kmeansEntropyCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate):
    f0 = open("NetFlowCalculations/Kmeans/Calculations/Entropy.Cluster0."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f1 = open("NetFlowCalculations/Kmeans/Calculations/Entropy.Cluster1."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f0.write("Time,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets")
    f1.write("Time,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets")

    df = getEntropyData(silkFile, start, stop, frequency, interval)
    #df.to_pickle("NetFlow/Kmeans/RawData/TestingDataEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    #df = pd.read_pickle("NetFlow/Kmeans/RawData/TestingDataEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    timeStamps, measurements = structureDataEntropy(df)

    prediction = KMeans(n_clusters=2, random_state=0, n_init="auto").fit_predict(measurements)
    count0 = 0 
    count1 = 0
    for i in range(len(prediction)):
        if prediction[i] == 0:
            f0.write("\n"  + str(timeStamps[i]) + "," +str(measurements[i][0])+ "," +str(measurements[i][1]) + "," +str(measurements[i][2]) + "," +str(measurements[i][3]) + "," +str(measurements[i][4]) + "," +str(measurements[i][5]) + "," +str(measurements[i][6]) + "," +str(measurements[i][7]) + "," +str(measurements[i][8]))
            count0 +=1
        elif prediction[i] == 1:
            f1.write("\n" + str(timeStamps[i])+ "," +str(measurements[i][0])+ "," +str(measurements[i][1]) + "," +str(measurements[i][2]) + "," +str(measurements[i][3]) + "," +str(measurements[i][4]) + "," +str(measurements[i][5]) + "," +str(measurements[i][6]) + "," +str(measurements[i][7]) + "," +str(measurements[i][8]))
            count1 += 1
    
    f0.close()
    f1.close()


systemId = "oslo-gw"
silkFile ="/home/linneafg/silk-data/RawDataFromFilter/two-hours-2011-01-02_10-11-sorted.rw"
start = "2011-01-02 10:00:00"
stop = "2011-01-02 12:00:00"
frequency = timedelta(minutes=1)
interval = timedelta(minutes=5)

'''kmeansEntropyCalculation(silkFile, start, stop, systemId, frequency, interval)'''