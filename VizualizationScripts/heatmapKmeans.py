import math
from matplotlib.colors import LinearSegmentedColormap
import pandas as pd
import numpy as np

import matplotlib.pyplot as plt
import seaborn as sns

from datetime import datetime, timedelta

def makeHeatMapKmeans(dataset, attackDate):
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
    f1_scores = []
    precision_scores = []
    tpr_scores = []
    accuracy_scores = []
    fpr_scores = []
    fnr_scores = []

    
    clusterFrequency = timedelta(minutes=15)

    for systemId in systems:
        print(systemId)
        
        start = startTime
        intervalTime = (stopTime - startTime).total_seconds()/clusterFrequency.total_seconds()

        truePositivesFields = 0
        falsePositivesFields = 0
        falseNegativesFields = 0
        trueNegativesFields = 0

        truePositivesCombined5min = 0
        falsePositivesCombined5min = 0
        falseNegativesCombined5min = 0
        trueNegativesCombined5min = 0

        truePositivesCombined10min = 0
        falsePositivesCombined10min = 0
        falseNegativesCombined10min = 0
        trueNegativesCombined10min = 0

        truePositivesCombined15min = 0
        falsePositivesCombined15min = 0
        falseNegativesCombined15min = 0
        trueNegativesCombined15min = 0
        if dataset == "NetFlow":
            #Loop for every minute in a week
            for i in range(math.ceil(intervalTime)):
                stop = start + clusterFrequency
                data = pd.read_csv("Calculations"+ fileString+ "/Kmeans/"+dataset+"/Scores.Fields.attack."+str(attackDate)+ ".stopTime."+stop.strftime("%H.%M.%S")+ "."+str(systemId)+ ".csv")
                
                if len(data) != 0:
                    truePositivesFields += data["TP"][0]
                    falsePositivesFields += data["FP"][0]
                    trueNegativesFields += data["TN"][0]
                    falseNegativesFields += data["FN"][0]

                
                
                dataCombined = pd.read_csv("Calculations"+ fileString+ "/Kmeans/"+dataset+"/Scores.Combined."+ str(int(timedelta(minutes = 5).total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime."+stop.strftime("%H.%M.%S")+ "."+str(systemId)+ ".csv")
                if len(dataCombined) != 0:
                    truePositivesCombined5min += dataCombined["TP"][0]
                    falsePositivesCombined5min += dataCombined["FP"][0]
                    trueNegativesCombined5min += dataCombined["TN"][0]
                    falseNegativesCombined5min += dataCombined["FN"][0]
                

                dataCombined = pd.read_csv("Calculations"+ fileString+ "/Kmeans/"+dataset+"/Scores.Combined."+ str(int(timedelta(minutes = 10).total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime."+stop.strftime("%H.%M.%S")+ "."+str(systemId)+ ".csv")
                if len(dataCombined) != 0:
                    truePositivesCombined10min += dataCombined["TP"][0]
                    falsePositivesCombined10min += dataCombined["FP"][0]
                    trueNegativesCombined10min += dataCombined["TN"][0]
                    falseNegativesCombined10min += dataCombined["FN"][0]
                

                start += clusterFrequency
        else:
            data = pd.read_csv("Calculations"+ fileString+ "/Kmeans/"+dataset+"/Scores.Fields.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
            
            if len(data) != 0:
                truePositivesFields += data["TP"][0]
                falsePositivesFields += data["FP"][0]
                trueNegativesFields += data["TN"][0]
                falseNegativesFields += data["FN"][0]

            
            
            dataCombined = pd.read_csv("Calculations"+ fileString+ "/Kmeans/"+dataset+"/Scores.Combined."+ str(int(timedelta(minutes = 5).total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
            if len(dataCombined) != 0:
                truePositivesCombined5min += dataCombined["TP"][0]
                falsePositivesCombined5min += dataCombined["FP"][0]
                trueNegativesCombined5min += dataCombined["TN"][0]
                falseNegativesCombined5min += dataCombined["FN"][0]
            

            dataCombined = pd.read_csv("Calculations"+ fileString+ "/Kmeans/"+dataset+"/Scores.Combined."+ str(int(timedelta(minutes = 10).total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
            if len(dataCombined) != 0:
                truePositivesCombined10min += dataCombined["TP"][0]
                falsePositivesCombined10min += dataCombined["FP"][0]
                trueNegativesCombined10min += dataCombined["TN"][0]
                falseNegativesCombined10min += dataCombined["FN"][0]
        if dataset == "NetFlow":
            clusterFrequency = timedelta(minutes=30)
            start = startTime
            intervalTime = (stopTime - startTime).total_seconds()/clusterFrequency.total_seconds()
            #Loop for every minute in a week
            for i in range(math.ceil(intervalTime)):
                stop = start + clusterFrequency

                dataCombined = pd.read_csv("Calculations"+ fileString+ "/Kmeans/"+dataset+"/Scores.Combined."+ str(int(timedelta(minutes = 15).total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
                if len(dataCombined) != 0:
                    truePositivesCombined15min += dataCombined["TP"][0]
                    falsePositivesCombined15min += dataCombined["FP"][0]
                    trueNegativesCombined15min += dataCombined["TN"][0]
                    falseNegativesCombined15min += dataCombined["FN"][0]
            start += clusterFrequency
        else:
            dataCombined = pd.read_csv("Calculations"+ fileString+ "/Kmeans/"+dataset+"/Scores.Combined."+ str(int(timedelta(minutes = 15).total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
            if len(dataCombined) != 0:
                truePositivesCombined15min += dataCombined["TP"][0]
                falsePositivesCombined15min += dataCombined["FP"][0]
                trueNegativesCombined15min += dataCombined["TN"][0]
                falseNegativesCombined15min += dataCombined["FN"][0]

        truePositivesEntropy5min = 0
        falsePositivesEntropy5min = 0
        falseNegativesEntropy5min = 0
        trueNegativesEntropy5min = 0
        data = pd.read_csv("Calculations"+ fileString+ "/Kmeans/"+dataset+"/Scores.Entropy."+ str(int(timedelta(minutes = 5).total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
        if len(data) != 0:
            truePositivesEntropy5min += data["TP"][0]
            falsePositivesEntropy5min += data["FP"][0]
            trueNegativesEntropy5min += data["TN"][0]
            falseNegativesEntropy5min += data["FN"][0]

        truePositivesEntropy10min = 0
        falsePositivesEntropy10min = 0
        falseNegativesEntropy10min = 0
        trueNegativesEntropy10min = 0
        data = pd.read_csv("Calculations"+ fileString+ "/Kmeans/"+dataset+"/Scores.Entropy."+ str(int(timedelta(minutes = 10).total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
        if len(data) != 0:
            truePositivesEntropy10min += data["TP"][0]
            falsePositivesEntropy10min += data["FP"][0]
            trueNegativesEntropy10min += data["TN"][0]
            falseNegativesEntropy10min += data["FN"][0]

        truePositivesEntropy15min = 0
        falsePositivesEntropy15min = 0
        falseNegativesEntropy15min = 0
        trueNegativesEntropy15min = 0
        data = pd.read_csv("Calculations"+ fileString+ "/Kmeans/"+dataset+"/Scores.Entropy."+ str(int(timedelta(minutes = 15).total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
        if len(data) != 0:
            truePositivesEntropy15min += data["TP"][0]
            falsePositivesEntropy15min += data["FP"][0]
            trueNegativesEntropy15min += data["TN"][0]
            falseNegativesEntropy15min += data["FN"][0]

        f1_scoresThisSystem = []
        precision_scoresThisSystem = []
        tpr_scoresThisSystem = []
        accuracy_scoresThisSystem = []
        fpr_scoresThisSystem = []
        fnr_scoresThisSystem = []

        print("\n")
            
        if falsePositivesFields == 0 and trueNegativesFields == 0 and truePositivesFields == 0 and falseNegativesFields == 0:
            print(falsePositivesFields,trueNegativesFields,truePositivesFields,falseNegativesFields)
            print("all where 0")
            f1_scoresThisSystem.append(None)
            precision_scoresThisSystem.append(None)
            tpr_scoresThisSystem.append(None)
            accuracy_scoresThisSystem.append(None)
            fpr_scoresThisSystem.append(None)
            fnr_scoresThisSystem.append(None)

        accuracy = (truePositivesFields + trueNegativesFields)/(truePositivesFields+trueNegativesFields+falsePositivesFields+falseNegativesFields)
        print(falsePositivesFields,trueNegativesFields,truePositivesFields,falseNegativesFields)
        if falsePositivesFields != 0 or trueNegativesFields != 0:
            fpr = falsePositivesFields/(falsePositivesFields + trueNegativesFields)
        else:
            fpr = None
        if falseNegativesFields != 0  or truePositivesFields != 0:
            fnr = falseNegativesFields/(falseNegativesFields + truePositivesFields)
        else:
            fnr = None
        if truePositivesFields != 0 or falsePositivesFields != 0:
            precision = truePositivesFields/(truePositivesFields+falsePositivesFields)
        else:
            precision = None
        if  falseNegativesFields != 0 or truePositivesFields != 0:
            recall = truePositivesFields/(truePositivesFields+ falseNegativesFields)
        else:
            recall = None
        if truePositivesFields != 0 or falsePositivesFields!= 0 or falseNegativesFields != 0:
            f1 =2*truePositivesFields/(2*truePositivesFields+falsePositivesFields+falseNegativesFields)
        else:
            f1 = None

        f1_scoresThisSystem.append(f1)
        precision_scoresThisSystem.append(precision)
        tpr_scoresThisSystem.append(recall)
        accuracy_scoresThisSystem.append(accuracy)
        fpr_scoresThisSystem.append(fpr)
        fnr_scoresThisSystem.append(fnr)

        if falsePositivesCombined5min == 0 and trueNegativesCombined5min == 0 and truePositivesCombined5min == 0 and falseNegativesCombined5min == 0:
            print(falsePositivesCombined5min,trueNegativesCombined5min,truePositivesCombined5min,falseNegativesCombined5min)
            print("all where 0")
            f1_scoresThisSystem.append(None)
            precision_scoresThisSystem.append(None)
            tpr_scoresThisSystem.append(None)
            accuracy_scoresThisSystem.append(None)
            fpr_scoresThisSystem.append(None)
            fnr_scoresThisSystem.append(None)

        accuracy = (truePositivesEntropy5min + trueNegativesEntropy5min)/(truePositivesEntropy5min+trueNegativesEntropy5min+falsePositivesEntropy5min+falseNegativesEntropy5min)
        print(falsePositivesEntropy5min,trueNegativesEntropy5min,truePositivesEntropy5min,falseNegativesEntropy5min)
        if falsePositivesEntropy5min != 0 or trueNegativesEntropy5min != 0:
            fpr = falsePositivesEntropy5min/(falsePositivesEntropy5min + trueNegativesEntropy5min)
        else:
            fpr = None
        if falseNegativesEntropy5min != 0  or truePositivesEntropy5min != 0:
            fnr = falseNegativesEntropy5min/(falseNegativesEntropy5min + truePositivesEntropy5min)
        else:
            fnr = None
        if truePositivesEntropy5min != 0 or falsePositivesEntropy5min != 0:
            precision = truePositivesEntropy5min/(truePositivesEntropy5min+falsePositivesEntropy5min)
        else:
            precision = None
        if  falseNegativesEntropy5min != 0 or truePositivesEntropy5min != 0:
            recall = truePositivesEntropy5min/(truePositivesEntropy5min+ falseNegativesEntropy5min)
        else:
            recall = None
        if truePositivesEntropy5min != 0 or falsePositivesEntropy5min!= 0 or falseNegativesEntropy5min != 0:
            f1 =2*truePositivesEntropy5min/(2*truePositivesEntropy5min+falsePositivesEntropy5min+falseNegativesEntropy5min)
        else:
            f1 = None

        f1_scoresThisSystem.append(f1)
        precision_scoresThisSystem.append(precision)
        tpr_scoresThisSystem.append(recall)
        accuracy_scoresThisSystem.append(accuracy)
        fpr_scoresThisSystem.append(fpr)
        fnr_scoresThisSystem.append(fnr)

        if falsePositivesEntropy10min == 0 and trueNegativesEntropy10min == 0 and truePositivesEntropy10min == 0 and falseNegativesEntropy10min == 0:
            print(falsePositivesEntropy10min,trueNegativesEntropy10min,truePositivesEntropy10min,falseNegativesEntropy10min)
            print("all where 0")
            f1_scoresThisSystem.append(None)
            precision_scoresThisSystem.append(None)
            tpr_scoresThisSystem.append(None)
            accuracy_scoresThisSystem.append(None)
            fpr_scoresThisSystem.append(None)
            fnr_scoresThisSystem.append(None)

        accuracy = (truePositivesEntropy10min + trueNegativesEntropy10min)/(truePositivesEntropy10min+trueNegativesEntropy10min+falsePositivesEntropy10min+falseNegativesEntropy10min)
        print(falsePositivesEntropy10min,trueNegativesEntropy10min,truePositivesEntropy10min,falseNegativesEntropy10min)
        if falsePositivesEntropy10min != 0 or trueNegativesEntropy10min != 0:
            fpr = falsePositivesEntropy10min/(falsePositivesEntropy10min + trueNegativesEntropy10min)
        else:
            fpr = None
        if falseNegativesEntropy10min != 0  or truePositivesEntropy10min != 0:
            fnr = falseNegativesEntropy10min/(falseNegativesEntropy10min + truePositivesEntropy10min)
        else:
            fnr = None
        if truePositivesEntropy10min != 0 or falsePositivesEntropy10min != 0:
            precision = truePositivesEntropy10min/(truePositivesEntropy10min+falsePositivesEntropy10min)
        else:
            precision = None
        if  falseNegativesEntropy10min != 0 or truePositivesEntropy10min != 0:
            recall = truePositivesEntropy10min/(truePositivesEntropy10min+ falseNegativesEntropy10min)
        else:
            recall = None
        if truePositivesEntropy10min != 0 or falsePositivesEntropy10min!= 0 or falseNegativesEntropy10min != 0:
            f1 =2*truePositivesEntropy10min/(2*truePositivesEntropy10min+falsePositivesEntropy10min+falseNegativesEntropy10min)
        else:
            f1 = None

        f1_scoresThisSystem.append(f1)
        precision_scoresThisSystem.append(precision)
        tpr_scoresThisSystem.append(recall)
        accuracy_scoresThisSystem.append(accuracy)
        fpr_scoresThisSystem.append(fpr)
        fnr_scoresThisSystem.append(fnr)

        if falsePositivesEntropy15min == 0 and trueNegativesEntropy15min == 0 and truePositivesEntropy15min == 0 and falseNegativesEntropy15min == 0:
            print(falsePositivesEntropy15min,trueNegativesEntropy15min,truePositivesEntropy15min,falseNegativesEntropy15min)
            print("all where 0")
            f1_scoresThisSystem.append(None)
            precision_scoresThisSystem.append(None)
            tpr_scoresThisSystem.append(None)
            accuracy_scoresThisSystem.append(None)
            fpr_scoresThisSystem.append(None)
            fnr_scoresThisSystem.append(None)

        accuracy = (truePositivesEntropy15min + trueNegativesEntropy15min)/(truePositivesEntropy15min+trueNegativesEntropy15min+falsePositivesEntropy15min+falseNegativesEntropy15min)
        print(falsePositivesEntropy15min,trueNegativesEntropy15min,truePositivesEntropy15min,falseNegativesEntropy15min)
        if falsePositivesEntropy15min != 0 or trueNegativesEntropy15min != 0:
            fpr = falsePositivesEntropy15min/(falsePositivesEntropy15min + trueNegativesEntropy15min)
        else:
            fpr = None
        if falseNegativesEntropy15min != 0  or truePositivesEntropy15min != 0:
            fnr = falseNegativesEntropy15min/(falseNegativesEntropy15min + truePositivesEntropy15min)
        else:
            fnr = None
        if truePositivesEntropy15min != 0 or falsePositivesEntropy15min != 0:
            precision = truePositivesEntropy15min/(truePositivesEntropy15min+falsePositivesEntropy15min)
        else:
            precision = None
        if  falseNegativesEntropy15min != 0 or truePositivesEntropy15min != 0:
            recall = truePositivesEntropy15min/(truePositivesEntropy15min+ falseNegativesEntropy15min)
        else:
            recall = None
        if truePositivesEntropy15min != 0 or falsePositivesEntropy15min!= 0 or falseNegativesEntropy15min != 0:
            f1 =2*truePositivesEntropy15min/(2*truePositivesEntropy15min+falsePositivesEntropy15min+falseNegativesEntropy15min)
        else:
            f1 = None

        f1_scoresThisSystem.append(f1)
        precision_scoresThisSystem.append(precision)
        tpr_scoresThisSystem.append(recall)
        accuracy_scoresThisSystem.append(accuracy)
        fpr_scoresThisSystem.append(fpr)
        fnr_scoresThisSystem.append(fnr)

        if falsePositivesCombined5min == 0 and trueNegativesCombined5min == 0 and truePositivesCombined5min == 0 and falseNegativesCombined5min == 0:
            print(falsePositivesCombined5min,trueNegativesCombined5min,truePositivesCombined5min,falseNegativesCombined5min)
            print("all where 0")
            f1_scoresThisSystem.append(None)
            precision_scoresThisSystem.append(None)
            tpr_scoresThisSystem.append(None)
            accuracy_scoresThisSystem.append(None)
            fpr_scoresThisSystem.append(None)
            fnr_scoresThisSystem.append(None)

        accuracy = (truePositivesCombined5min + trueNegativesCombined5min)/(truePositivesCombined5min+trueNegativesCombined5min+falsePositivesCombined5min+falseNegativesCombined5min)
        print(falsePositivesCombined5min,trueNegativesCombined5min,truePositivesCombined5min,falseNegativesCombined5min)
        if falsePositivesCombined5min != 0 or trueNegativesCombined5min != 0:
            fpr = falsePositivesCombined5min/(falsePositivesCombined5min + trueNegativesCombined5min)
        else:
            fpr = None
        if falseNegativesCombined5min != 0  or truePositivesCombined5min != 0:
            fnr = falseNegativesCombined5min/(falseNegativesCombined5min + truePositivesCombined5min)
        else:
            fnr = None
        if truePositivesCombined5min != 0 or falsePositivesCombined5min != 0:
            precision = truePositivesCombined5min/(truePositivesCombined5min+falsePositivesCombined5min)
        else:
            precision = None
        if  falseNegativesCombined5min != 0 or truePositivesCombined5min != 0:
            recall = truePositivesCombined5min/(truePositivesCombined5min+ falseNegativesCombined5min)
        else:
            recall = None
        if truePositivesCombined5min != 0 or falsePositivesCombined5min!= 0 or falseNegativesCombined5min != 0:
            f1 =2*truePositivesCombined5min/(2*truePositivesCombined5min+falsePositivesCombined5min+falseNegativesCombined5min)
        else:
            f1 = None

        f1_scoresThisSystem.append(f1)
        precision_scoresThisSystem.append(precision)
        tpr_scoresThisSystem.append(recall)
        accuracy_scoresThisSystem.append(accuracy)
        fpr_scoresThisSystem.append(fpr)
        fnr_scoresThisSystem.append(fnr)

        if falsePositivesCombined10min == 0 and trueNegativesCombined10min == 0 and truePositivesCombined10min == 0 and falseNegativesCombined10min == 0:
            print(falsePositivesCombined10min,trueNegativesCombined10min,truePositivesCombined10min,falseNegativesCombined10min)
            print("all where 0")
            f1_scoresThisSystem.append(None)
            precision_scoresThisSystem.append(None)
            tpr_scoresThisSystem.append(None)
            accuracy_scoresThisSystem.append(None)
            fpr_scoresThisSystem.append(None)
            fnr_scoresThisSystem.append(None)

        accuracy = (truePositivesCombined10min + trueNegativesCombined10min)/(truePositivesCombined10min+trueNegativesCombined10min+falsePositivesCombined10min +falseNegativesCombined10min )
        print(falsePositivesCombined10min ,trueNegativesCombined10min ,truePositivesCombined10min ,falseNegativesCombined10min )
        if falsePositivesCombined10min  != 0 or trueNegativesCombined10min  != 0:
            fpr = falsePositivesCombined10min /(falsePositivesCombined10min  + trueNegativesCombined10min )
        else:
            fpr = None
        if falseNegativesCombined10min  != 0  or truePositivesCombined10min  != 0:
            fnr = falseNegativesCombined10min /(falseNegativesCombined10min  + truePositivesCombined10min )
        else:
            fnr = None
        if truePositivesCombined10min  != 0 or falsePositivesCombined10min  != 0:
            precision = truePositivesCombined10min /(truePositivesCombined10min +falsePositivesCombined10min )
        else:
            precision = None
        if  falseNegativesCombined10min  != 0 or truePositivesCombined10min  != 0:
            recall = truePositivesCombined10min /(truePositivesCombined10min + falseNegativesCombined10min )
        else:
            recall = None
        if truePositivesCombined10min  != 0 or falsePositivesCombined10min != 0 or falseNegativesCombined10min  != 0:
            f1 =2*truePositivesCombined10min /(2*truePositivesCombined10min +falsePositivesCombined10min +falseNegativesCombined10min )
        else:
            f1 = None

        f1_scoresThisSystem.append(f1)
        precision_scoresThisSystem.append(precision)
        tpr_scoresThisSystem.append(recall)
        accuracy_scoresThisSystem.append(accuracy)
        fpr_scoresThisSystem.append(fpr)
        fnr_scoresThisSystem.append(fnr)

        if falsePositivesCombined15min  == 0 and trueNegativesCombined15min  == 0 and truePositivesCombined15min  == 0 and falseNegativesCombined15min  == 0:
            print(falsePositivesCombined15min ,trueNegativesCombined15min ,truePositivesCombined15min ,falseNegativesCombined15min )
            print("all where 0")
            f1_scoresThisSystem.append(None)
            precision_scoresThisSystem.append(None)
            tpr_scoresThisSystem.append(None)
            accuracy_scoresThisSystem.append(None)
            fpr_scoresThisSystem.append(None)
            fnr_scoresThisSystem.append(None)

        accuracy = (truePositivesCombined15min  + trueNegativesCombined15min )/(truePositivesCombined15min +trueNegativesCombined15min +falsePositivesCombined15min +falseNegativesCombined15min )
        print(falsePositivesCombined15min ,trueNegativesCombined15min ,truePositivesCombined15min ,falseNegativesCombined15min )
        if falsePositivesCombined15min  != 0 or trueNegativesCombined15min  != 0:
            fpr = falsePositivesCombined15min /(falsePositivesCombined15min  + trueNegativesCombined15min )
        else:
            fpr = None
        if falseNegativesCombined15min  != 0  or truePositivesCombined15min  != 0:
            fnr = falseNegativesCombined15min /(falseNegativesCombined15min  + truePositivesCombined15min )
        else:
            fnr = None
        if truePositivesCombined15min  != 0 or falsePositivesCombined15min  != 0:
            precision = truePositivesCombined15min /(truePositivesCombined15min +falsePositivesCombined15min )
        else:
            precision = None
        if  falseNegativesCombined15min  != 0 or truePositivesCombined15min  != 0:
            recall = truePositivesCombined15min /(truePositivesCombined15min + falseNegativesCombined15min )
        else:
            recall = None
        if truePositivesCombined15min  != 0 or falsePositivesCombined15min != 0 or falseNegativesCombined15min  != 0:
            f1 =2*truePositivesCombined15min /(2*truePositivesCombined15min +falsePositivesCombined15min +falseNegativesCombined15min )
        else:
            f1 = None
        

        f1_scoresThisSystem.append(f1)
        precision_scoresThisSystem.append(precision)
        tpr_scoresThisSystem.append(recall)
        accuracy_scoresThisSystem.append(accuracy)
        fpr_scoresThisSystem.append(fpr)
        fnr_scoresThisSystem.append(fnr)

        f1_scores.append(f1_scoresThisSystem)
        precision_scores.append(precision_scoresThisSystem)
        tpr_scores.append(tpr_scoresThisSystem)
        accuracy_scores.append(accuracy_scoresThisSystem)
        fpr_scores.append(fpr_scoresThisSystem)
        fnr_scores.append(fnr_scoresThisSystem)

    '''transposed_f1_scores = np.transpose(f1_scores)
    transposed_precision_scores = np.transpose(precision_scores)
    transposed_tpr_scores = np.transpose(tpr_scores)
    transposed_accuracy_scores = np.transpose(accuracy_scores)
    transposed_fpr_scores = np.transpose(fpr_scores)
    transposed_fnr_scores = np.transpose(fnr_scores)'''
    colors = ["#E9D4C7","#CB997E", "#3A2D32"]
    x_labels = ['Fields', 'Entropy, 5 min interval', 'Entropy, 10 min interval', 'Entropy, 15 min interval','Combined, 5 min interval', 'Combined, 10 min interval', 'Combined, 15 min interval']

    cmap = LinearSegmentedColormap.from_list("custom_cmap", colors)

    fig, ax = plt.subplots(figsize=(10, 10))
    sns.heatmap(f1_scores, annot=True, fmt=".3f", cmap=cmap, ax=ax)
    
    ax.set_xticklabels(x_labels, rotation = 30, ha='right')
    ax.set_yticklabels(systems, rotation = 30,ha='right')

    # Manually create a colorbar
    cbar = ax.collections[0].colorbar
    cbar.set_ticks([0, 0.5, 0.99])
    cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("F1-scores for K-means clustering")
    fig.tight_layout()
    fig.savefig("Plots/Kmeans/Attack"+ fileString+ "/"+dataset+"/F1.png", dpi=500)
    plt.close(fig)



    fig, ax = plt.subplots(figsize=(10, 10))
    sns.heatmap(precision_scores, annot=True, fmt=".3f", cmap=cmap, ax=ax)
    
    ax.set_xticklabels(x_labels, rotation = 30, ha='right')
    ax.set_yticklabels(systems, rotation = 30,ha='right')

    # Manually create a colorbar
    cbar = ax.collections[0].colorbar
    cbar.set_ticks([0, 0.5, 0.99])
    cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("Precision for K-means clustering")
    fig.tight_layout()
    fig.savefig("Plots/Kmeans/Attack"+ fileString+ "/"+dataset+"/Precision.png", dpi=500)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(10, 10))
    sns.heatmap(tpr_scores, annot=True, fmt=".3f", cmap=cmap, ax=ax)
    
    ax.set_xticklabels(x_labels, rotation = 30, ha='right')
    ax.set_yticklabels(systems, rotation = 30,ha='right')

    # Manually create a colorbar
    cbar = ax.collections[0].colorbar
    cbar.set_ticks([0, 0.5, 0.99])
    cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("TPR for K-means clustering")
    fig.tight_layout()
    fig.savefig("Plots/Kmeans/Attack"+ fileString+ "/"+dataset+"/TPR.png", dpi=500)
    plt.close(fig)


    fig, ax = plt.subplots(figsize=(10, 10))
    sns.heatmap(accuracy_scores, annot=True, fmt=".3f", cmap=cmap, ax=ax)
    
    ax.set_xticklabels(x_labels, rotation = 30, ha='right')
    ax.set_yticklabels(systems, rotation = 30,ha='right')

    # Manually create a colorbar
    cbar = ax.collections[0].colorbar
    cbar.set_ticks([0, 0.5, 0.99])
    cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("Accuracy for K-means clustering")
    fig.tight_layout()
    fig.savefig("Plots/Kmeans/Attack"+ fileString+ "/"+dataset+"/Accuracy.png", dpi=500)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(10, 10))
    sns.heatmap(fpr_scores, annot=True, fmt=".3f", cmap=cmap, ax=ax)
    
    ax.set_xticklabels(x_labels, rotation = 30, ha='right')
    ax.set_yticklabels(systems, rotation = 30,ha='right')

    # Manually create a colorbar
    cbar = ax.collections[0].colorbar
    cbar.set_ticks([0, 0.5, 0.99])
    cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("FPR for K-means clustering")
    fig.tight_layout()
    fig.savefig("Plots/Kmeans/Attack"+ fileString+ "/"+dataset+"/FPR.png", dpi=500)
    plt.close(fig)


    fig, ax = plt.subplots(figsize=(10, 10))
    sns.heatmap(fnr_scores, annot=True, fmt=".3f", cmap=cmap, ax=ax)
    
    ax.set_xticklabels(x_labels, rotation = 30, ha='right')
    ax.set_yticklabels(systems, rotation = 30,ha='right')

    # Manually create a colorbar
    cbar = ax.collections[0].colorbar
    cbar.set_ticks([0, 0.5, 0.99])
    cbar.set_ticklabels(['Low', 'Medium', 'High'])
    plt.title("FNR for K-means clustering")
    fig.tight_layout()
    fig.savefig("Plots/Kmeans/Attack"+ fileString+ "/"+dataset+"/FNR.png", dpi=500)
    plt.close(fig)
    

makeHeatMapKmeans("Telemetry", "24.03.23")