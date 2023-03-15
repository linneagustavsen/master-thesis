from sklearn.cluster import KMeans
import pandas as pd
from .GetData import *
from HelperFunctions.StructureData import *
from .IsAttackFlow import *
from .StructureData import *

def kmeansCombinedCalculation(systemId, attackDate):
    f0 = open("NetFlowCalculations/Kmeans/Calculations/Combined.Cluster0.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f1 = open("NetFlowCalculations/Kmeans/Calculations/Combined.Cluster1.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f0.write("Time,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets,is_attack")
    f1.write("Time,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets,is_attack")
    
    df = pd.read_pickle("NetFlow/Kmeans/RawData/TestingDataCombined.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    timeStamps, measurements = structureDataEntropy(df)

    prediction = KMeans(n_clusters=2, random_state=0, n_init="auto").fit_predict(measurements)
    count0 = 0 
    count1 = 0
    for i in range(len(prediction)):
        if prediction[i] == 0:
            f0.write("\n"  + str(timeStamps[i]) + "," +str(measurements[i][2])+ "," +str(measurements[i][3])+"," +str(measurements[i][4])+ "," +str(measurements[i][5])+ "," +str(measurements[i][6])+ "," +str(measurements[i][7])+ "," +str(measurements[i][8]) + "," +str(measurements[i][9])+ "," +str(measurements[i][10])+ "," +str(measurements[i][11])+ "," +str(measurements[i][12])+ "," +str(measurements[i][13])+ "," +str(measurements[i][14])+ "," +str(measurements[i][15])+ "," +str(measurements[i][17])+ "," +str(measurements[i][18])+ "," +str(measurements[i][19])+ "," +str(measurements[i][20])+ "," +str(measurements[i][21])+ "," +str(measurements[i][22])+ "," +str(measurements[i][23])+ "," +str(measurements[i][24])+ "," +str(measurements[i][25])+ "," +str(int(isAttackFlow(measurements[i][0], measurements[i][1]))))
            count0 +=1
        elif prediction[i] == 1:
            f1.write("\n"  + str(timeStamps[i]) + "," +str(measurements[i][2])+ "," +str(measurements[i][3])+"," +str(measurements[i][4])+ "," +str(measurements[i][5])+ "," +str(measurements[i][6])+ "," +str(measurements[i][7])+ "," +str(measurements[i][8]) + "," +str(measurements[i][9])+ "," +str(measurements[i][10])+ "," +str(measurements[i][11])+ "," +str(measurements[i][12])+ "," +str(measurements[i][13])+ "," +str(measurements[i][14])+ "," +str(measurements[i][15])+ "," +str(measurements[i][17])+ "," +str(measurements[i][18])+ "," +str(measurements[i][19])+ "," +str(measurements[i][20])+ "," +str(measurements[i][21])+ "," +str(measurements[i][22])+ "," +str(measurements[i][23])+ "," +str(measurements[i][24])+ "," +str(measurements[i][25])+ "," +str(int(isAttackFlow(measurements[i][0], measurements[i][1]))))
            count1 += 1
    
    f0.close()
    f1.close()


systemId = "oslo-gw"
silkFile ="/home/linneafg/silk-data/RawDataFromFilter/two-hours-2011-01-02_10-11-sorted.rw"
start = "2011-01-02 10:00:00"
stop = "2011-01-02 12:00:00"
frequency = timedelta(minutes=1)
interval = timedelta(minutes=5)

'''kmeansCombinedCalculation(silkFile, start, stop, systemId, frequency, interval)'''