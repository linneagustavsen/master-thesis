

from datetime import datetime, timedelta
import json
import math
from pathlib import Path
import numpy as np
import pandas as pd
from ast import literal_eval


def makeRandomForestTable(featureSet, dataset, interval, attackDate):
    if dataset == "NetFlow":
        systems = ["trd-gw", "ifi2-gw5", "bergen-gw3", "tromso-gw5", "teknobyen-gw1",  "hoytek-gw2"]
    
        anonymizedSystems = ["AR1", "AR2", "AR3", "AR4", "VR", "CR3"]
    else:
        systems = ["trd-gw", "ifi2-gw5", "bergen-gw3", "tromso-gw5", "teknobyen-gw1", "teknobyen-gw2", "oslo-gw1", "hoytek-gw2", "hovedbygget-gw", "narvik-gw3", "narvik-gw4", "ma2-gw",  "tromso-fh-gw", "narvik-kv-gw", "stangnes-gw", "rodbergvn-gw2"]
    
        anonymizedSystems = ["AR1", "AR2", "AR3", "AR4", "VR", "CR1", "CR2", "CR3", "CR4", "CR5", "CR6", "CR7", "CR8", "CR9", "CR10", "CR11"]

    systemNames = []
    f1_scores = []
    precision_scores = []
    tpr_scores = []
    accuracy_scores = []
    fpr_scores = []
    fnr_scores = []

    startTime = datetime.strptime("2023-03-24 14:00:00", '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime("2023-03-24 18:00:00", '%Y-%m-%d %H:%M:%S')
    
    for systemId in systems:
        print(systemId)
        truePositives = 0
        falsePositives = 0
        falseNegatives = 0
        trueNegatives = 0
        if dataset == "NetFlow":
            if featureSet != "Entropy":
                start = startTime
                intervalTime = (stopTime - startTime).total_seconds()/timedelta(minutes=15).total_seconds()

                totalPositives = 0
                totalNegatives = 0
                #Loop for every minute in a week
                for i in range(math.ceil(intervalTime)):
                    stop = start + timedelta(minutes=15)
                    if featureSet == "Fields" or "FieldsNoIP":
                        data = pd.read_csv("Calculations2403/Kmeans/"+dataset+"/Scores.Fields.attack."+str(attackDate)+ ".stopTime."+stop.strftime("%H.%M.%S")+ "."+str(systemId)+ ".csv")
                    else:
                        data = pd.read_csv("Calculations2403/Kmeans/"+dataset+"/Scores.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".stopTime."+stop.strftime("%H.%M.%S")+ "."+str(systemId)+ ".csv")
                    if len(data) == 0:
                        print("There was no data")
                        continue
                    totalPositives += data["TP"][0]
                    totalNegatives += data["FP"][0]
                    totalNegatives += data["TN"][0]
                    totalPositives += data["FN"][0]
                    start += timedelta(minutes=15)
            if featureSet == "Fields":
                alerts = pd.read_csv("Calculations2403/RandomForest/NetFlow/Alerts.Fields.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
                labels  = alerts["real_label"]
                for label in labels:
                    if label == 1:
                        truePositives += 1
                    else:
                        falsePositives += 1
                falseNegatives = totalPositives - truePositives
                trueNegatives = totalNegatives - falsePositives
                print(totalPositives, totalNegatives)
                print(totalNegatives/totalPositives)
                print(totalPositives/totalNegatives)
                print(totalNegatives+ totalPositives)
            elif featureSet ==  "FieldsNoIP":
                alerts = pd.read_csv("Calculations2403/RandomForest/NetFlow/AlertsNoIP.Fields.attack."+str(attackDate)+ "."+ str(systemId)+ ".csv")
                labels  = alerts["real_label"]
                for label in labels:
                    if label == 1:
                        truePositives += 1
                    else:
                        falsePositives += 1
                falseNegatives = totalPositives - truePositives
                trueNegatives = totalNegatives - falsePositives
            elif featureSet == "CombinedNoIP":
                alerts = pd.read_csv("Calculations2403/RandomForest/NetFlow/AlertsNoIP.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
                labels  = alerts["real_label"]
                for label in labels:
                    if label == 1:
                        truePositives += 1
                    else:
                        falsePositives += 1
                falseNegatives = totalPositives - truePositives
                trueNegatives = totalNegatives - falsePositives
            elif featureSet == "Combined":
                alerts = pd.read_csv("Calculations2403/RandomForest/NetFlow/Alerts.Combined."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
                labels  = alerts["real_label"]
                for label in labels:
                    if label == 1:
                        truePositives += 1
                    else:
                        falsePositives += 1
                falseNegatives = totalPositives - truePositives
                trueNegatives = totalNegatives - falsePositives

            else:
                data = pd.read_csv("Calculations2403/RandomForest/"+dataset+"/Score."+featureSet+ "."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
        else:
            if featureSet == "Fields":
                data = pd.read_csv("Calculations2403/RandomForest/"+dataset+"/Score."+featureSet+ ".attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
                #print("Score."+featureSet+ ".attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
            else:
                data = pd.read_csv("Calculations2403/RandomForest/"+dataset+"/Score."+featureSet+ "."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
        
        if dataset == "NetFlow" and featureSet != "Entropy":
            if truePositives != 0 and falseNegatives != 0 and falsePositives != 0 or trueNegatives != 0:
                accuracy = (truePositives + trueNegatives)/(truePositives+trueNegatives+falsePositives+falseNegatives)
            else:
                accuracy = None
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
        else:
            if data.empty:
                f1_scores.append(None)
                precision_scores.append(None)
                tpr_scores.append(None)
                accuracy_scores.append(None)
                fpr_scores.append(None)
                fnr_scores.append(None)
                continue

            confusion_matrix = data["confusion_matrix"].values
            confusion_matrix = literal_eval(str(confusion_matrix).replace("['", "").replace("']", "").replace("' '", ",").replace(" ", ",").replace(",,,,,", ",").replace(",,,,", ",").replace(",,,", ",").replace(",,", ",").replace("[,", "["))
            '''print(confusion_matrix)
            print(len(confusion_matrix))'''


            if len(confusion_matrix) == 1:
                truePositives = 0
                falsePositives = 0
                falseNegatives = 0
                trueNegatives = confusion_matrix[0][0]
            else:
                truePositives = confusion_matrix[1][1]
                falsePositives = confusion_matrix[0][1]
                falseNegatives = confusion_matrix[1][0]
                trueNegatives = confusion_matrix[0][0]
            totalPositives = truePositives+falseNegatives
            totalNegatives = falsePositives+trueNegatives
            print(truePositives+falseNegatives, falsePositives+trueNegatives)
            print(totalNegatives/totalPositives)
            print(totalPositives/totalNegatives)
            print(totalNegatives+ totalPositives)
            print(truePositives, falsePositives, trueNegatives, falseNegatives)
            accuracy = (truePositives + trueNegatives)/(truePositives+trueNegatives+falsePositives+falseNegatives)
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
    def exp_tex(float_number):
        if isinstance(float_number, str):
            return float_number
        if np.isnan(float_number):
            return "undef"
        """
        Returns a string representation of the scientific
        notation of the given number formatted for use with
        LaTeX or Mathtext.
        """
        neg = False
        if float_number == 0.0:
            return r"0"
        elif float_number == 1:
            print(float_number)
            return r"1"
        elif float_number >= 0.01:
            return "{:.3f}".format(float_number)
        elif float_number < 0.0:
            neg = True

        exponent = np.floor(np.log10(abs(float_number)))
        mantissa = float_number/10**exponent
        if neg:
            mantissa = -mantissa
        mantissa_format = str(mantissa)[0:3]
        return "${0}\\cdot10^{{{1}}}$".format(mantissa_format, str(int(exponent)))

    
    df = pd.DataFrame(dict(Routers=anonymizedSystems,
                        F1=f1_scores,
                        Precision=precision_scores,
                        TPR=tpr_scores,
                        Accuracy=accuracy_scores,
                        FPR=fpr_scores,
                        FNR=fnr_scores))
    df = df.sort_values(['F1', 'FPR'], ascending=False)
    df = df.applymap(lambda x:exp_tex(x))
    print(df.to_latex(index=False, escape = False))


def makeRandomForestTableAttackTypes(featureSet, dataset, dataType, metric, interval, attackDate):
    if attackDate == "08.03.23":
        fileString = "0803"
    elif attackDate == "17.03.23":
        fileString = "1703"
    elif attackDate == "24.03.23":
        fileString = "2403"
    if dataset == "NetFlow":
        systems = ["trd-gw", "ifi2-gw5", "bergen-gw3", "tromso-gw5", "teknobyen-gw1",  "hoytek-gw2"]
    
        anonymizedSystems = ["AR1", "AR2", "AR3", "AR4", "VR", "CR3"]
        tableColumns = ["", "AR1", "AR2", "AR3", "AR4", "VR", "CR3"]
    else:
        systems = ["trd-gw", "ifi2-gw5", "bergen-gw3", "tromso-gw5", "teknobyen-gw1", "teknobyen-gw2", "oslo-gw1", "hoytek-gw2", "hovedbygget-gw", "narvik-gw3", "narvik-gw4", "ma2-gw",  "tromso-fh-gw", "narvik-kv-gw", "stangnes-gw", "rodbergvn-gw2"]
    
        anonymizedSystems = ["AR1", "AR2", "AR3", "AR4", "VR", "CR1", "CR2", "CR3", "CR4", "CR5", "CR6", "CR7", "CR8", "CR9", "CR10", "CR11"]
        tableColumns = ["","AR1", "AR2", "AR3", "AR4", "VR", "CR1", "CR2", "CR3", "CR4", "CR5", "CR6", "CR7", "CR8", "CR9", "CR10", "CR11"]

    systemNames = []
    f1_scores = []
    precision_scores = []
    tpr_scores = []
    accuracy_scores = []
    fpr_scores = []
    fnr_scores = []

    startTime = datetime.strptime("2023-03-24 14:00:00", '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime("2023-03-24 18:00:00", '%Y-%m-%d %H:%M:%S')
    if interval == timedelta(minutes = 5):
        windowSize = "5min"
    elif interval == timedelta(minutes = 10):
        windowSize = "10min"
    elif interval == timedelta(minutes = 15):
        windowSize = "15min"

    p = Path('Detections' + fileString +"_"+ windowSize +"_"+ metric)
    attackTypes = ["UDP Flood",
                    "SlowLoris", 
                    "Ping Flood", 
                    "Slow Read",
                    "Blacknurse",
                    "SYN Flood",
                    "R.U.D.Y",
                    "Xmas",
                    "UDP Flood and SlowLoris",
                    "Ping Flood and R.U.D.Y",
                    "All types"]
    attackTypes = {"UDP Flood": 0,
                    "SlowLoris": 0,
                    "Ping Flood": 0,
                    "Slow Read": 0,
                    "Blacknurse": 0,
                    "SYN Flood": 0,
                    "R.U.D.Y": 0,
                    "Xmas": 0,
                    "UDP Flood and SlowLoris": 0,
                    "Ping Flood and R.U.D.Y": 0,
                    "All types": 0}
    

    precision_scores = []
    for attack in attackTypes:
        precision_scores_this_system = [attack]
        for systemId in systems:
            print(systemId)
            
            if interval == 0:
                fileName =str(p)+ "/"+dataType+"/"+dataset+"/ScoresAttacks."+featureSet+".attack."+str(attackDate)+ "."+str(systemId)+ ".json"
            else:
                fileName = str(p)+ "/"+dataType+"/"+dataset+"/ScoresAttacks."+featureSet+"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".json"

            jsonFile = open(fileName, 'r')
            data = json.load(jsonFile)
            truePositives = data[attack]["TP"]
            falsePositives = data[attack]["FP"]
            if truePositives != 0 or falsePositives != 0:
                precision = truePositives/(truePositives+falsePositives)
            else:
                precision = np.nan

            print(truePositives, falsePositives, precision)
        

            precision_scores_this_system.append(precision)
        precision_scores.append(precision_scores_this_system)
    print(precision_scores)     
    def exp_tex(float_number):
        print(float_number)
        if isinstance(float_number, str):
            return float_number
        if np.isnan(float_number):
            print(float_number)
            return "undef"
        """
        Returns a string representation of the scientific
        notation of the given number formatted for use with
        LaTeX or Mathtext.
        """
        neg = False
        if float_number == 0.0:
            return r"0"
        elif float_number == 1:
            print(float_number)
            return r"1"
        elif float_number >= 0.01:
            return "{:.3f}".format(float_number)
        elif float_number < 0.0:
            neg = True

        exponent = np.floor(np.log10(abs(float_number)))
        mantissa = float_number/10**exponent
        if neg:
            mantissa = -mantissa
        mantissa_format = str(mantissa)[0:3]
        return "${0}\\cdot10^{{{1}}}$".format(mantissa_format, str(int(exponent)))

    
    df = pd.DataFrame(precision_scores, columns=tableColumns)
    print(df)
    df = df.applymap(lambda x:exp_tex(x))
    print(df.to_latex(index=False, escape = False))

makeRandomForestTableAttackTypes("SYNDestinationIPEntropy", "NetFlow", "Entropy", "F1", timedelta(minutes=5), "24.03.23")