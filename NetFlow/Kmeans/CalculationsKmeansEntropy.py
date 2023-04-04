from sklearn.cluster import KMeans
from HelperFunctions.GetData import *
from HelperFunctions.StructureData import *

'''
    Do K-means clustering on entropy data and write clusters to file
    Input:  silkFile:   string, File with flow records sorted on time
            start:      string, indicating the start time of the data wanted
            stop:       string, indicating the stop time of the data wanted
            systemId:   string, name of the system to collect and calculate on
            frequency:  timedelta object, frequency of metric calculation
            interval:   timedelta object, size of the sliding window which the calculation is made on
            attackDate: string, date of the attack the calculations are made on
'''
def kmeansEntropyCalculation(silkFile, start, stop, systemId, frequency, interval, attackDate):
    f0 = open("Calculations/Kmeans/NetFlow/Entropy.Cluster0."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f1 = open("Calculations/Kmeans/NetFlow/Entropy.Cluster1."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    f0.write("Time,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets,real_label")
    f1.write("Time,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets,real_label")

    df = getEntropyDataNetFlow(silkFile, start, stop, frequency, interval)
    #df.to_pickle("NetFlow/Kmeans/RawData/TestingDataEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    #df = pd.read_pickle("NetFlow/Kmeans/RawData/TestingDataEntropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    timeStamps, measurements = structureDataEntropy(df)

    prediction = KMeans(n_clusters=2, random_state=0, n_init="auto").fit_predict(measurements)
    count0 = 0 
    count1 = 0
    for i in range(len(prediction)):
        line = "\n"  + str(timeStamps[i])
        for measurement in measurements[i]:
            line += "," + str(measurement)
        timestamp = datetime.strptime(timeStamps[i], ("%Y-%m-%d %H:%M"))
        line += "," +str(int(isAttack(timestamp)))
        
        if prediction[i] == 0:
            f0.write(line)
            count0 +=1
        elif prediction[i] == 1:
            f1.write(line)
            count1 += 1
    
    f0.close()
    f1.close()