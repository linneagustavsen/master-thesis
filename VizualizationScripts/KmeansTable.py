

from datetime import timedelta,datetime
import math
import numpy as np
import pandas as pd
from ast import literal_eval


def makeRandomForestTable(featureSet, dataset, interval, attackDate):
    systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]



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
    systemNames = []
    f1_scores = []
    precision_scores = []
    tpr_scores = []
    accuracy_scores = []
    fpr_scores = []
    fnr_scores = []

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
        else:
            truePositives = 0
            falsePositives = 0
            falseNegatives = 0
            trueNegatives = 0
            counter = 0
            data = pd.read_csv("Calculations"+ fileString+ "/Kmeans/"+dataset+"/Scores."+featureSet+ "."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
            if len(data) == 0:
                print("There was no data")
                f1_scores.append(None)
                precision_scores.append(None)
                tpr_scores.append(None)
                accuracy_scores.append(None)
                fpr_scores.append(None)
                fnr_scores.append(None)
                continue
            truePositives += data["TP"][0]
            print("true positives", truePositives)
            falsePositives += data["FP"][0]
            print("false Positives", falsePositives)
            trueNegatives += data["TN"][0]
            print("true negatives", trueNegatives)
            falseNegatives += data["FN"][0]
            print("false negatives", falseNegatives)
            print("\n")
            
        if falsePositives == 0 and trueNegatives == 0 and truePositives == 0 and falseNegatives == 0:
            print(falsePositives,trueNegatives,truePositives,falseNegatives)
            print("all where 0")
            f1_scores.append(None)
            precision_scores.append(None)
            tpr_scores.append(None)
            accuracy_scores.append(None)
            fpr_scores.append(None)
            fnr_scores.append(None)
            continue
        accuracy = (truePositives + trueNegatives)/(truePositives+trueNegatives+falsePositives+falseNegatives)
        print(falsePositives,trueNegatives,truePositives,falseNegatives)
        if falsePositives != 0 or trueNegatives != 0:
            fpr = falsePositives/(falsePositives + trueNegatives)
        else:
            fpr = None
        if falseNegatives != 0  or truePositives != 0:
            fnr = falseNegatives/(falseNegatives + truePositives)
        else:
            fnr = None
        if truePositives != 0 or falsePositives != 0:
            precision = truePositives/(truePositives+falsePositives)
        else:
            precision = None
        if  falseNegatives != 0 or truePositives != 0:
            recall = truePositives/(truePositives+ falseNegatives)
        else:
            recall = None
        if truePositives != 0 or falsePositives!= 0 or falseNegatives != 0:
            f1 =2*truePositives/(2*truePositives+falsePositives+falseNegatives)
        else:
            f1 = None
        

        f1_scores.append(f1)
        precision_scores.append(precision)
        tpr_scores.append(recall)
        accuracy_scores.append(accuracy)
        fpr_scores.append(fpr)
        fnr_scores.append(fnr)

    #print(f1_scores)
    #print(precision_scores)
    #print(tpr_scores)
    #print(accuracy_scores)
    #print(fpr_scores)
    #print(fnr_scores)

    '''print(len(f1_scores))
    print(len(precision_scores))
    print(len(tpr_scores))
    print(len(accuracy_scores))
    print(len(fpr_scores))
    print(len(fnr_scores))'''

    df = pd.DataFrame(dict(Routers=systems,
                        F1=f1_scores,
                        Precision=precision_scores,
                        TPR=tpr_scores,
                        Accuracy=accuracy_scores,
                        FPR=fpr_scores,
                        FNR=fnr_scores))
    df = df.sort_values(['F1', 'FPR'], ascending=False)
    print(df.to_latex(index=False, float_format="{:.3f}".format,))

makeRandomForestTable("Fields", "NetFlow", timedelta(minutes=15), "17.03.23")