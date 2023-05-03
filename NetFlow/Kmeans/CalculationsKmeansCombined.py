from pathlib import Path
from sklearn.cluster import KMeans
import pandas as pd
from HelperFunctions.GetData import *
from HelperFunctions.StructureData import *
from HelperFunctions.StructureData import *
from NetFlow.Kmeans.ClusterLabelling import labelCluster
from NetFlow.Kmeans.MakeDataSet import makeDataSetKmeansNetFlow

'''
    Do K-means clustering on entropy and field data and write clusters to file
    Input:  
            testingSet: pandas dataframe, data set to detect on
            systemId:   string, name of the system to collect and calculate on
            interval:   timedelta object, size of the sliding window which the calculation is made on
            attackDate: string, date of the attack the calculations are made on
'''
def kmeansCombinedCalculation(silkFile, start, stop, clusterFrequency, frequency, systemId, interval, attackDate):
    p = Path('Calculations')
    q = p / 'Kmeans' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    
    ipP = Path('IPCalculations')
    ipPath = ipP / 'Kmeans'
    if not ipPath.exists():
        ipPath.mkdir(parents=True, exist_ok=False)
    #Makes datetime objects of the input times
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    intervalTime = (stopTime - startTime).total_seconds()/clusterFrequency.total_seconds()
 
    #Loop for every minute in a week
    for i in range(math.ceil(intervalTime)):
        stopTime = startTime + clusterFrequency

        f0 = open(str(q) + "/Combined.Cluster0."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime."+str(stopTime)+ "."+str(systemId)+ ".csv", "a")
        f1 = open(str(q) + "/Combined.Cluster1."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime."+str(stopTime)+ "."+str(systemId)+ ".csv", "a")
        f0.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets,packet_size_entropy,packet_size_entropy_rate,number_of_packets,number_of_bytes,real_label")
        f1.write("sTime,eTime,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets,packet_size_entropy,packet_size_entropy_rate,number_of_packets,number_of_bytes,real_label")
        f0IP = open(str(ipPath) + "/Combined.Cluster0."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime."+str(stopTime)+ "."+str(systemId)+ ".csv", "a")
        f1IP = open(str(ipPath) + "/Combined.Cluster1."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime."+str(stopTime)+ "."+str(systemId)+ ".csv", "a")
        f0IP.write("sTime,eTime,srcIP,dstIP,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,nextHopIP,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets,packet_size_entropy,packet_size_entropy_rate,number_of_packets,number_of_bytes,real_label")
        f1IP.write("sTime,eTime,srcIP,dstIP,srcPort,dstPort,protocol,packets,bytes,fin,syn,rst,psh,ack,urg,ece,cwr,duration,nextHopIP,entropy_ip_source,entropy_rate_ip_source,entropy_ip_destination,entropy_rate_ip_destination,entropy_flow,entropy_rate_flow,number_of_flows,icmp_ratio,number_of_icmp_packets,packet_size_entropy,packet_size_entropy_rate,number_of_packets,number_of_bytes,real_label")
        
        cluster = open(str(q) + "/Combined.ClusterLabelling."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime."+str(stopTime)+ "."+str(systemId)+ ".csv", "a")
        cluster.write("AttackCluster,Davies-bouldin-score,ClusterDiameter0,ClusterDiameter1,ClusterSize0,ClusterSize1")
        
        testingSet = makeDataSetKmeansNetFlow(silkFile, startTime, stopTime, frequency, interval)
        if len(testingSet) < 2:
            startTime += clusterFrequency
            continue
        sTime, eTime, measurements = structureData(testingSet)
        label = measurements[:,-1]
        measurements = measurements[:, :-1]

        sTime = pd.to_datetime(sTime)
        eTime = pd.to_datetime(eTime)

        prediction = KMeans(n_clusters=2, random_state=0, n_init="auto").fit_predict(measurements)
        attackCluster, db, cd0, cd1, counter0, counter1 = labelCluster(measurements, prediction, 0.5, 0, 0)
        cluster.write("\n"+ str(attackCluster) + "," + str(db) + "," + str(cd0) + "," + str(cd1)+ "," + str(counter0)+ "," + str(counter1))

        count0 = 0 
        count1 = 0
        for i in range(len(prediction)):
            line = "\n"  + sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ") + "," + eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ")
            lineIPs = "\n"  + sTime[i].strftime("%Y-%m-%dT%H:%M:%SZ") + "," + eTime[i].strftime("%Y-%m-%dT%H:%M:%SZ")
            for j in range(len(measurements[i])):
                lineIPs += "," + str(measurements[i][j])
                #Skip the IP fields
                if j == 0 or j == 1 or j == 16:
                    continue
                line += "," + str(measurements[i][j])
            lineIPs += "," +str(label[i])
            line += "," +str(label[i])
            
            if prediction[i] == 0:
                f0.write(line)
                f0IP.write(lineIPs)
                count0 +=1
            elif prediction[i] == 1:
                f1.write(line)
                f1IP.write(lineIPs)
                count1 += 1
        
        f0.close()
        f1.close()
        f0IP.close()
        f1IP.close()
        cluster.close()
        startTime += clusterFrequency
