from sklearn.cluster import KMeans
import pandas as pd
from HelperFunctions.GetData import *
from HelperFunctions.StructureData import *
from datetime import datetime,timedelta
from HelperFunctions.IsAttack import *

'''
    Do K-means clustering on entropy data and write clusters to file
    Input:  start:      string, indicating the start time of the data to detect on
            stop:       string, indicating the stop time of the data to detect on
            systemId:   string, name of the system to collect and calculate on  
            if_name:    string, interface name, 
            interval:   timedelta object, size of the sliding window which the calculation is made on,
            frequency:  timedelta object, frequency of metric calculation,
            attackDate: string, date of the attack the calculations are made on
'''
def detectionKmeansEntropyTelemetry(start, stop, systemId, if_name, interval, frequency, attackDate):
    f0 = open("Calculations/Kmeans/Telemetry/Entropy.Cluster0."+ str(systemId) + "." + str(if_name).replace("/","-")+ "." + str(attackDate) + ".csv", "a")
    f1 = open("Calculations/Kmeans/Telemetry/Entropy.Cluster1."+ str(systemId) + "." + str(if_name).replace("/","-")+ "." + str(attackDate) + ".csv", "a")
    f0.write("Time,entropy_packet_size,entropy_rate_packet_size,real_label")
    f1.write("Time,entropy_packet_size,entropy_rate_packet_size,real_label")

    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    df = getEntropyData(startTime, stopTime, systemId, if_name, interval, frequency)
    #df.to_pickle("NetFlow/Kmeans/RawData/Testing.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    #df = pd.read_pickle("NetFlow/Kmeans/RawData/Testing.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    timeStamps, measurements = structureDataTelemetry(df)

    prediction = KMeans(n_clusters=2, random_state=0, n_init="auto").fit_predict(measurements)
    count0 = 0 
    count1 = 0

    for i in range(len(prediction)):
        line = "\n"  + timeStamps[i].strftime("%Y-%m-%dT%H:%M:%SZ")
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
    print(count0)
    print(count1)
    
    f0.close()
    f1.close()

'''start = "2022-09-21 01:00:00"
stop = "2022-09-22 00:00:00"
systemId = "trd-gw"
if_name = "xe-0/1/0"
interval = timedelta(minutes = 5)
frequency = timedelta(minutes = 1)
attackDate = "21.09"
detectionKmeansEntropyTelemetry(start, stop, systemId, if_name, interval, frequency, attackDate)'''