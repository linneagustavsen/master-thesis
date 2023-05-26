

import numpy as np
import pandas as pd
from ast import literal_eval


def makeRandomForestTable(featureSet, interval, attackDate):
    systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5"]
    systemNames = []
    f1_scores = []
    precision_scores = []
    tpr_scores = []
    accuracy_scores = []
    fpr_scores = []
    fnr_scores = []

    for systemId in systems:
        print(systemId)
        if featureSet == "Fields" or featureSet ==  "FieldsNoIP":
            data = pd.read_csv("Calculations2403/RandomForest/NetFlow/Score."+featureSet+ ".attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
            print("Score."+featureSet+ ".attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
        else:
            data = pd.read_csv("Calculations2403/RandomForest/NetFlow/Score."+featureSet+ "."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv")
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

        if len(data["confusion_matrix"].values) == 1:
            print(confusion_matrix)
            accuracy = data["accuracy"][0]
            f1 = data["f1"][0]
            recall = data["recall"][0]
            precision = data["precision"][0]
        else:
            accuracy = data["accuracy"][1]
            f1 = data["f1"][1]
            recall = data["recall"][1]
            precision = data["precision"][1]

        f1_scores.append(f1)
        precision_scores.append(precision)
        tpr_scores.append(recall)
        accuracy_scores.append(accuracy)
        if len(confusion_matrix) > 1:
            fpr_scores.append(int(confusion_matrix[0][1])/(int(confusion_matrix[0][1]) + int(confusion_matrix[0][0])))
            print(fpr_scores[-1])
            fnr_scores.append(int(confusion_matrix[1][0])/(int(confusion_matrix[1][0]) + int(confusion_matrix[1][1])))
            print(fnr_scores[-1])
        else:
            fpr_scores.append(None)
            fnr_scores.append(None)
        

    print(f1_scores)
    print(precision_scores)
    print(tpr_scores)
    print(accuracy_scores)
    print(fpr_scores)
    print(fnr_scores)

    print(len(f1_scores))
    print(len(precision_scores))
    print(len(tpr_scores))
    print(len(accuracy_scores))
    print(len(fpr_scores))
    print(len(fnr_scores))
    df = pd.DataFrame(dict(Routers=systems,
                        F1=f1_scores,
                        Precision=precision_scores,
                        TPR=tpr_scores,
                        Accuracy=accuracy_scores,
                        FPR=fpr_scores,
                        FNR=fnr_scores))

    print(df.to_latex(index=False))

makeRandomForestTable("Fields", 0, "24.03.23")