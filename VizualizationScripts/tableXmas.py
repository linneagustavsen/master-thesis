import math
from pathlib import Path
from matplotlib.colors import LinearSegmentedColormap
import pandas as pd
import numpy as np

import matplotlib.pyplot as plt
import seaborn as sns

from datetime import datetime, timedelta

from sklearn.metrics import auc

def makeHeatMapXmas(metric, attackDate):
    systems = ["trd-gw", "ifi2-gw5", "bergen-gw3", "tromso-gw5", "teknobyen-gw1", "teknobyen-gw2", "oslo-gw1", "hoytek-gw2", "hovedbygget-gw", "narvik-gw3", "narvik-gw4", "ma2-gw",  "tromso-fh-gw", "narvik-kv-gw", "stangnes-gw", "rodbergvn-gw2"]
    
    anonymizedSystems = ["AR1", "AR2", "AR3", "AR4", "VR", "CR1", "CR2", "CR3", "CR4", "CR5", "CR6", "CR7", "CR8", "CR9", "CR10", "CR11"]

    systems = ["trd-gw", "ifi2-gw5", "bergen-gw3", "tromso-gw5", "teknobyen-gw1",  "hoytek-gw2"]
    
    anonymizedSystems = ["AR1", "AR2", "AR3", "AR4", "VR", "CR3"]

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
    systemCounter =0 
    p = Path('Detections' + fileString +"_5min_"+ metric)

    for systemId in systems:
        
        print(systemId)
        '''f1_scoresThisSystem = []
        precision_scoresThisSystem = []
        tpr_scoresThisSystem = []
        accuracy_scoresThisSystem = []
        fpr_scoresThisSystem = []
        fnr_scoresThisSystem = []'''
        truePositives = 0
        falsePositives = 0
        falseNegatives = 0
        trueNegatives = 0
        dataFile = str(p) + "/TopKFlows/NetFlow/Scores.TopKFlows.attack."+str(attackDate)+ "."+str(systemId)+ ".csv"

        if not Path(dataFile).exists():
            print("File doesnt exist", dataFile)
            f1_scores.append(np.nan)
            precision_scores.append(np.nan)
            tpr_scores.append(np.nan)
            accuracy_scores.append(np.nan)
            fpr_scores.append(np.nan)
            fnr_scores.append(np.nan)
            continue
    
        data = pd.read_csv(dataFile)
    
        if len(data) != 0:
            truePositives += data["TP"][0]
            falsePositives += data["FP"][0]
            trueNegatives += data["TN"][0]
            falseNegatives += data["FN"][0]

        
        if falsePositives == 0 and truePositives == 0:
            print("all where 0")
            f1_scores.append(np.nan)
            precision_scores.append(np.nan)
            tpr_scores.append(np.nan)
            accuracy_scores.append(np.nan)
            fpr_scores.append(np.nan)
            fnr_scores.append(np.nan)
        else:
            print(truePositives, falsePositives, trueNegatives, falseNegatives)
            accuracy = (truePositives + trueNegatives)/(truePositives+trueNegatives+falsePositives+falseNegatives)
            if falsePositives != 0 or trueNegatives != 0:
                fpr = falsePositives/(falsePositives + trueNegatives)
            else:
                fpr = np.nan
            if falseNegatives != 0  or truePositives != 0:
                fnr = falseNegatives/(falseNegatives + truePositives)
            else:
                fnr = np.nan
            if truePositives != 0 or falsePositives != 0:
                precision = truePositives/(truePositives+falsePositives)
            else:
                precision = np.nan
            if  falseNegatives != 0 or truePositives != 0:
                recall = truePositives/(truePositives+ falseNegatives)
            else:
                recall = np.nan
            if truePositives != 0 or falsePositives!= 0 or falseNegatives != 0:
                f1 =2*truePositives/(2*truePositives+falsePositives+falseNegatives)
            else:
                f1 = np.nan

            f1_scores.append(f1)
            precision_scores.append(precision)
            tpr_scores.append(recall)
            accuracy_scores.append(accuracy)
            fpr_scores.append(fpr)
            fnr_scores.append(fnr)

    
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

makeHeatMapXmas( "TPR", "24.03.23")