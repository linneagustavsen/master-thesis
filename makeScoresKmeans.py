

from datetime import timedelta,datetime
import math
from pathlib import Path
import numpy as np
import pandas as pd


def makeScoresKmeans(featureSet, dataset, interval, attackDate):
    if dataset == "NetFlow":
        systems = ["tromso-gw5",  "teknobyen-gw1", "hoytek-gw2", "bergen-gw3","trd-gw", "ifi2-gw5"]
    else:
        systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", "oslo-gw1"]

    if attackDate == "08.03.23":
        fileString = "0803"
        startTime = datetime.strptime("2023-03-08 14:15:00", '%Y-%m-%d %H:%M:%S')
        stopTime = datetime.strptime("2023-03-08 16:00:00", '%Y-%m-%d %H:%M:%S')
    elif attackDate == "17.03.23":
        fileString="1703"
        startTime = datetime.strptime("2023-03-17 11:00:00", '%Y-%m-%d %H:%M:%S')
        stopTime = datetime.strptime("2023-03-17 13:00:00", '%Y-%m-%d %H:%M:%S')
    elif attackDate == "24.03.23":
        fileString = "2403"
        startTime = datetime.strptime("2023-03-24 14:00:00", '%Y-%m-%d %H:%M:%S')
        stopTime = datetime.strptime("2023-03-24 18:00:00", '%Y-%m-%d %H:%M:%S')

    if interval != timedelta(minutes=15):
        clusterFrequency = timedelta(minutes=15)
    else:
        clusterFrequency = timedelta(minutes=30)

    for systemId in systems:
        print(systemId)
        if featureSet == "Fields":
            start = startTime
            intervalTime = (stopTime - startTime).total_seconds()/clusterFrequency.total_seconds()

            truePositives = 0
            falsePositives = 0
            falseNegatives = 0
            trueNegatives = 0
            counter = 0
            #Loop for every minute in a week
            for i in range(math.ceil(intervalTime)):
                stop = start + clusterFrequency
                data = pd.read_csv("Calculations"+ fileString+ "/Kmeans/"+dataset+"/Scores."+featureSet+ ".attack."+str(attackDate)+ ".stopTime."+stop.strftime("%H.%M.%S")+ "."+str(systemId)+ ".csv")
                
                if len(data) == 0:
                    print("There was no data")
                    continue
                truePositives += data["TP"][0]
                falsePositives += data["FP"][0]
                trueNegatives += data["TN"][0]
                falseNegatives += data["FN"][0]
                counter += 1
                start += clusterFrequency
            scoreFile = open("Calculations/Kmeans/"+dataset+"/Scores."+featureSet+ ".attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
            scoreFile.write("TP,FP,FN,TN")
            scoreFile.write("\n"+str(truePositives) + "," + str(falsePositives) + "," + str(falseNegatives) + "," + str(trueNegatives))
        elif featureSet == "Combined":
            start = startTime
            intervalTime = (stopTime - startTime).total_seconds()/clusterFrequency.total_seconds()

            truePositives = 0
            falsePositives = 0
            falseNegatives = 0
            trueNegatives = 0
            counter = 0
            #Loop for every minute in a week
            for i in range(math.ceil(intervalTime)):
                stop = start + clusterFrequency
                data = pd.read_csv("Calculations"+ fileString+ "/Kmeans/"+dataset+"/Scores."+featureSet+ "."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime."+stop.strftime("%H.%M.%S")+ "."+str(systemId)+ ".csv")
                if len(data) == 0:
                    print("There was no data")
                    continue
                print(stop)
                truePositives += data["TP"][0]
                print("true positives", truePositives)
                falsePositives += data["FP"][0]
                print("false Positives", falsePositives)
                trueNegatives += data["TN"][0]
                print("true negatives", trueNegatives)
                falseNegatives += data["FN"][0]
                print("false negatives", falseNegatives)
                print("\n")
                counter += 1
                start += clusterFrequency
            scoreFile = open("Calculations/Kmeans/"+dataset+"/Scores."+featureSet+ "."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
            scoreFile.write("TP,FP,FN,TN")
            scoreFile.write("\n"+str(truePositives) + "," + str(falsePositives) + "," + str(falseNegatives) + "," + str(trueNegatives))
        else:


            truePositives = 0
            falsePositives = 0
            falseNegatives = 0
            trueNegatives = 0
            attackCluster = pd.read_csv("Calculations"+fileString+"/Kmeans/Telemetry/Entropy.ClusterLabelling."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
            if attackCluster.empty:
                return
            if attackCluster["AttackCluster"][0] == 0:
                cluster =  pd.read_csv("Calculations"+fileString+"/Kmeans/Telemetry/Entropy.Cluster0."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
                '''attackClusterDiameter = attackCluster["ClusterDiameter0"][0]
                nonAttackClusterDiameter = attackCluster["ClusterDiameter1"][0]'''

                nonAttackCluster = pd.read_csv("Calculations"+fileString+"/Kmeans/Telemetry/Entropy.Cluster1."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
            
            elif attackCluster["AttackCluster"][0] == 1:
                cluster =  pd.read_csv("Calculations"+fileString+"/Kmeans/Telemetry/Entropy.Cluster1."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
                '''attackClusterDiameter =  attackCluster["ClusterDiameter1"][0]
                nonAttackClusterDiameter = attackCluster["ClusterDiameter0"][0]'''

                nonAttackCluster = pd.read_csv("Calculations"+fileString+"/Kmeans/Telemetry/Entropy.Cluster0."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
            
            labelsForNonAttackCluster = nonAttackCluster["real_label"]

            for label in labelsForNonAttackCluster:
                if label == 0:
                    trueNegatives += 1
                elif label == 1:
                    falseNegatives += 1

            attackClusterLabels = cluster["real_label"]
            for label in attackClusterLabels:
                if label == 0:
                    falsePositives += 1
                elif label == 1:
                    truePositives += 1

            scoreFile = open("Calculations/Kmeans/"+dataset+"/Scores."+featureSet+ "."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
            scoreFile.write("TP,FP,FN,TN")
            scoreFile.write("\n"+str(truePositives) + "," + str(falsePositives) + "," + str(falseNegatives) + "," + str(trueNegatives))
        
def makeScoresXmas(featureSet, dataset, dataType, metric, attackDate):
    if dataset == "NetFlow":
        systems = ["tromso-gw5",  "teknobyen-gw1", "hoytek-gw2", "bergen-gw3","trd-gw", "ifi2-gw5"]
    else:
        systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", "oslo-gw1"]

    if attackDate == "08.03.23":
        fileString = "0803"
        startTime = datetime.strptime("2023-03-08 14:15:00", '%Y-%m-%d %H:%M:%S')
        stopTime = datetime.strptime("2023-03-08 16:00:00", '%Y-%m-%d %H:%M:%S')
    elif attackDate == "17.03.23":
        fileString="1703"
        startTime = datetime.strptime("2023-03-17 11:00:00", '%Y-%m-%d %H:%M:%S')
        stopTime = datetime.strptime("2023-03-17 13:00:00", '%Y-%m-%d %H:%M:%S')
    elif attackDate == "24.03.23":
        fileString = "2403"
        startTime = datetime.strptime("2023-03-24 14:00:00", '%Y-%m-%d %H:%M:%S')
        stopTime = datetime.strptime("2023-03-24 18:00:00", '%Y-%m-%d %H:%M:%S')


    for systemId in systems:
        print(systemId)

        positives = 0
        negatives = 0
        truePositives = 0
        falsePositives = 0
        falseNegatives = 0
        trueNegatives = 0
        p = Path('Detections' + fileString +"_5min_"+ metric)
       
        data = pd.read_csv(str(p) + "/Kmeans/"+dataset+"/Scores.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
            
        if len(data) == 0:
            print("There was no data")
            continue
        positives += data["TP"][0]
        negatives += data["FP"][0]
        negatives += data["TN"][0]
        positives += data["FN"][0]
        data = pd.read_csv(str(p) + "/"+dataType+"/"+dataset+"/Scores."+featureSet+ ".attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
        truePositives = data["TP"][0]
        falsePositives += data["FP"][0]
        trueNegatives = negatives - falsePositives
        falseNegatives = positives - truePositives
        scoreFile = open("Calculations/"+dataType+"/"+dataset+"/Scores."+featureSet+ ".attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
        scoreFile.write("TP,FP,FN,TN")
        scoreFile.write("\n"+str(truePositives) + "," + str(falsePositives) + "," + str(falseNegatives) + "," + str(trueNegatives))
        

'''makeScoresKmeans("Fields", "Telemetry", 0, "17.03.23")
makeScoresKmeans("Fields", "NetFlow", 0, "17.03.23")

makeScoresKmeans("Combined", "Telemetry", timedelta(minutes=5), "17.03.23")
makeScoresKmeans("Combined", "Telemetry", timedelta(minutes=10), "17.03.23")
makeScoresKmeans("Combined", "Telemetry", timedelta(minutes=15), "17.03.23")'''

'''makeScoresKmeans("Entropy", "Telemetry", timedelta(minutes=5), "17.03.23")
makeScoresKmeans("Entropy", "Telemetry", timedelta(minutes=10), "17.03.23")
makeScoresKmeans("Entropy", "Telemetry", timedelta(minutes=15), "17.03.23")'''

'''makeScoresKmeans("Combined", "NetFlow", timedelta(minutes=5), "17.03.23")
makeScoresKmeans("Combined", "NetFlow", timedelta(minutes=10), "17.03.23")
makeScoresKmeans("Combined", "NetFlow", timedelta(minutes=15), "17.03.23")

makeScoresKmeans("Fields", "Telemetry", 0, "24.03.23")
makeScoresKmeans("Fields", "NetFlow", 0, "24.03.23")

makeScoresKmeans("Combined", "Telemetry", timedelta(minutes=5), "24.03.23")
makeScoresKmeans("Combined", "Telemetry", timedelta(minutes=10), "24.03.23")
makeScoresKmeans("Combined", "Telemetry", timedelta(minutes=15), "24.03.23")


makeScoresKmeans("Combined", "NetFlow", timedelta(minutes=5), "24.03.23")
makeScoresKmeans("Combined", "NetFlow", timedelta(minutes=10), "24.03.23")
makeScoresKmeans("Combined", "NetFlow", timedelta(minutes=15), "24.03.23")


makeScoresXmas("Xmas", "NetFlow", 0, "24.03.23")'''

makeScoresXmas("TopKFlows", "NetFlow", "TopKFlows", "F1", "24.03.23")