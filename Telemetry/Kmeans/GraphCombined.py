from sklearn.cluster import KMeans
import pandas as pd
from HelperFunctions.GetData import *
from datetime import timedelta
from HelperFunctions.MakePlot import *

'''
    Do K-means clustering on entropy data and field data and make plots of the results
    Input:  systemId:   string, name of the system to collect and calculate on  
            interval:   timedelta object, size of the sliding window which the calculation is made on,
            attackDate: string, date of the attack the calculations are made on
'''
def kmeansGraphCombined(systemId, interval, attackDate):
    df = pd.read_pickle("Telemetry/Kmeans/Data/TestingSetCombined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    measurements = df.values
    timeStamps = pd.read_pickle("Telemetry/Kmeans/RawData/Testing.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")["_time"].to_numpy()

    prediction = KMeans(n_clusters=2, random_state=0, n_init="auto").fit_predict(measurements)
    count0 = 0 
    count1 = 0

    time0 = []
    time1 = []

    queueA0 = []
    queueA1 = []

    queueC0 = []
    queueC1 = []

    pkts0 = []
    pkts1 = []

    bytes0 = []
    bytes1 = []

    entropy0 = []
    entropy1 = []

    entropyR0 = []
    entropyR1 = []

    for i in range(len(prediction)):
        if prediction[i] == 0:
            time0.append(timeStamps[i])
            queueA0.append(measurements[i][0])
            queueC0.append(measurements[i][1])
            pkts0.append(measurements[i][2])
            bytes0.append(measurements[i][3])
            entropy0.append(measurements[i][4])
            entropyR0.append(measurements[i][5])

            time1.append(timeStamps[i])
            queueA1.append(None)
            queueC1.append(None)
            pkts1.append(None)
            bytes1.append(None)
            entropy1.append(None)
            entropyR1.append(None)

            count0 +=1
        elif prediction[i] == 1:
            time1.append(timeStamps[i])
            queueA1.append(measurements[i][0])
            queueC1.append(measurements[i][1])
            pkts1.append(measurements[i][2])
            bytes1.append(measurements[i][3])
            entropy1.append(measurements[i][4])
            entropyR1.append(measurements[i][5])

            time0.append(timeStamps[i])
            queueA0.append(None)
            queueC0.append(None)
            pkts0.append(None)
            bytes0.append(None)
            entropy0.append(None)
            entropyR0.append(None)

            count1 += 1
    print(count0)
    print(count1)
    makePlot(queueA0, time0, "Combined Average queue in cluster 0", "Plots/Kmeans/Telemetry/" + str(attackDate) + ".")
    makePlot(queueA1, time1, "Combined Average queue in cluster 1", "Plots/Kmeans/Telemetry/" + str(attackDate) + ".")

    makePlot(queueC0, time0, "Combined Current queue in cluster 0", "Plots/Kmeans/Telemetry/" + str(attackDate) + ".")
    makePlot(queueC1, time1, "Combined Current queue in cluster 1", "Plots/Kmeans/Telemetry/" + str(attackDate) + ".")

    makePlot(pkts0, time0, "Combined Packets per sec in cluster 0", "Plots/Kmeans/Telemetry/" + str(attackDate) + ".")
    makePlot(pkts1, time1, "Combined Packets per sec in cluster 1", "Plots/Kmeans/Telemetry/" + str(attackDate) + ".")

    makePlot(bytes0, time0, "Combined Bytes per sec in cluster 0", "Plots/Kmeans/Telemetry/" + str(attackDate) + ".")
    makePlot(bytes1, time1, "Combined Bytes per sec in cluster 1", "Plots/Kmeans/Telemetry/" + str(attackDate) + ".")
    makePlot(entropy0, time0, "Combined Entropy in cluster 0", "Plots/Kmeans/Telemetry/" + str(attackDate) + ".")
    makePlot(entropy1, time1, "Combined Entropy in cluster 1", "Plots/Kmeans/Telemetry/" + str(attackDate) + ".")

    makePlot(entropyR0, time0, "Combined Entropy rate in cluster 0", "Plots/Kmeans/Telemetry/" + str(attackDate) + ".")
    makePlot(entropyR1, time1, "Combined Entropy rate in cluster 1", "Plots/Kmeans/Telemetry/" + str(attackDate) + ".")
    

systemId = "trd-gw"
interval = timedelta(minutes = 5)
frequency = timedelta(minutes = 1)
attackDate = "21.09"
kmeansGraphCombined(systemId, interval, attackDate)