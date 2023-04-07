from sklearn.cluster import KMeans
from HelperFunctions.GetData import *
from HelperFunctions.StructureData import *
from HelperFunctions.MakePlot import *

'''
    Do K-means clustering on field data and make plots of the results
    Input:  start:      string, indicating the start time of the data to detect on
            stop:       string, indicating the stop time of the data to detect on
            systemId:   string, name of the system to collect and calculate on  
            if_name:    string, interface name 
            fields:     list of strings, features to incorporate in the clustering
            attackDate: string, date of the attack the calculations are made on
'''
def kmeansGraph(start, stop, systemId, if_name, fields, attackDate):
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    df = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), systemId, if_name, fields)
    #df.to_pickle("NetFlow/Kmeans/RawData/Testing.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    #df = pd.read_pickle("NetFlow/Kmeans/RawData/Testing.attack."+str(attackDate)+ "."+str(systemId)+ ".pkl")
    timeStamps, measurements = structureDataTelemetry(df)

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

    for i in range(len(prediction)):
        if prediction[i] == 0:
            time0.append(timeStamps[i])
            queueA0.append(measurements[i][0])
            queueC0.append(measurements[i][1])
            pkts0.append(measurements[i][2])
            bytes0.append(measurements[i][3])

            time1.append(timeStamps[i])
            queueA1.append(None)
            queueC1.append(None)
            pkts1.append(None)
            bytes1.append(None)

            count0 +=1
        elif prediction[i] == 1:
            time1.append(timeStamps[i])
            queueA1.append(measurements[i][0])
            queueC1.append(measurements[i][1])
            pkts1.append(measurements[i][2])
            bytes1.append(measurements[i][3])

            time0.append(timeStamps[i])
            queueA0.append(None)
            queueC0.append(None)
            pkts0.append(None)
            bytes0.append(None)

            count1 += 1
    print(count0)
    print(count1)
    makePlot(queueA0, time0, "Average queue in cluster 0", "Plots/Kmeans/Telemetry/attack." + str(attackDate) + ".")
    makePlot(queueA1, time1, "Average queue in cluster 1", "Plots/Kmeans/Telemetry/attack." + str(attackDate) + ".")

    makePlot(queueC0, time0, "Current queue in cluster 0", "Plots/Kmeans/Telemetry/attack." + str(attackDate) + ".")
    makePlot(queueC1, time1, "Current queue in cluster 1", "Plots/Kmeans/Telemetry/attack." + str(attackDate) + ".")

    makePlot(pkts0, time0, "Packets per sec in cluster 0", "Plots/Kmeans/Telemetry/attack." + str(attackDate) + ".")
    makePlot(pkts1, time1, "Packets per sec in cluster 1", "Plots/Kmeans/Telemetry/attack." + str(attackDate) + ".")

    makePlot(bytes0, time0, "Bytes per sec in cluster 0", "Plots/Kmeans/Telemetry/attack." + str(attackDate) + ".")
    makePlot(bytes1, time1, "Bytes per sec in cluster 1", "Plots/Kmeans/Telemetry/attack." + str(attackDate) + ".")
    
'''
start = "2022-09-21 01:00:00"
stop = "2022-09-22 00:00:00"
systemId = "trd-gw"
if_name = "xe-0/1/0"
fields = ["egress_queue_info__0__avg_buffer_occupancy", "egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets"]
attackDate = "21.09"

kmeansGraph(start, stop, systemId, if_name, fields, attackDate)'''