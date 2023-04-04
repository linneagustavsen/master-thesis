from sklearn.cluster import KMeans
from HelperFunctions.GetData import *
from HelperFunctions.StructureData import *
from HelperFunctions.MakePlot import *
from datetime import timedelta,datetime

'''
    Do K-means clustering on entropy data and make plots of the results
    Input:  start:      string, indicating the start time of the data to detect on
            stop:       string, indicating the stop time of the data to detect on
            systemId:   string, name of the system to collect and calculate on  
            if_name:    string, interface name, 
            interval:   timedelta object, size of the sliding window which the calculation is made on,
            frequency:  timedelta object, frequency of metric calculation,
            attackDate: string, date of the attack the calculations are made on
'''
def kmeansGraphEntropy(start, stop, systemId, if_name, interval, frequency, attackDate):
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    df = getEntropyData(startTime, stopTime, systemId, if_name, interval, frequency)
    #df.to_pickle("NetFlow/Kmeans/RawData/Testing.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    #df = pd.read_pickle("NetFlow/Kmeans/RawData/Testing.Entropy."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    timeStamps, measurements = structureDataTelemetry(df)

    prediction = KMeans(n_clusters=2, random_state=0, n_init="auto").fit_predict(measurements)
    count0 = 0 
    count1 = 0

    time0 = []
    time1 = []

    entropy0 = []
    entropy1 = []

    entropyR0 = []
    entropyR1 = []

    for i in range(len(prediction)):
        if prediction[i] == 0:
            time0.append(timeStamps[i])
            entropy0.append(measurements[i][0])
            entropyR0.append(measurements[i][1])

            time1.append(timeStamps[i])
            entropy1.append(None)
            entropyR1.append(None)

            count0 +=1
        elif prediction[i] == 1:
            time1.append(timeStamps[i])
            entropy1.append(measurements[i][0])
            entropyR1.append(measurements[i][1])

            time0.append(timeStamps[i])
            entropy0.append(None)
            entropyR0.append(None)

            count1 += 1
    print(count0)
    print(count1)
    makePlot(entropy0, time0, "Entropy in cluster 0", "Plots/Kmeans/Telemetry/" + str(attackDate) + ".")
    makePlot(entropy1, time1, "Entropy in cluster 1", "Plots/Kmeans/Telemetry/")

    makePlot(entropyR0, time0, "Entropy rate in cluster 0", "Plots/Kmeans/Telemetry/" + str(attackDate) + ".")
    makePlot(entropyR1, time1, "Entropy rate in cluster 1", "Plots/Kmeans/Telemetry/" + str(attackDate) + ".")
    

start = "2022-09-21 01:00:00"
stop = "2022-09-22 00:00:00"
systemId = "trd-gw"
if_name = "xe-0/1/0"
interval = timedelta(minutes = 5)
frequency = timedelta(minutes = 1)
attackDate = "21.09"

kmeansGraphEntropy(start, stop, systemId, if_name, interval, frequency, attackDate)