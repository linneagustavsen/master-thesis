

from datetime import datetime, timedelta
import math
import numpy as np
import pandas as pd
from ast import literal_eval


def makeRandomForestTable(featureSet, dataset, interval, attackDate):
    if dataset == "NetFlow":
        systems = ["tromso-gw5",  "teknobyen-gw1", "hoytek-gw2", "bergen-gw3","trd-gw", "ifi2-gw5"]
    else:
        systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", "oslo-gw1"]
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

    
    df = pd.DataFrame(dict(Routers=systems,
                        F1=f1_scores,
                        Precision=precision_scores,
                        TPR=tpr_scores,
                        Accuracy=accuracy_scores,
                        FPR=fpr_scores,
                        FNR=fnr_scores))
    df = df.sort_values(['F1', 'FPR'], ascending=False)
    df = df.applymap(lambda x:exp_tex(x))
    print(df.to_latex(index=False, escape = False))

makeRandomForestTable("Combined", "Telemetry", timedelta(minutes=15), "24.03.23")