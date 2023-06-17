from datetime import timedelta
from pathlib import Path
from numpy import mean

import pandas as pd


def getWeight(y_field, systemId, interval, dataType, dataSet, attackDate):
    p = Path('ThresholdDecision')
    
    if dataType == "Entropy":
        decisionPath = p / 'Entropy'
    elif dataType == "Threshold":
        decisionPath = p / 'Threshold'
    elif dataType == "TopKFlows":
        decisionPath = p / 'TopKFlows'
    elif dataType == "RandomForest":
        decisionPath = p / 'RandomForest'
    elif dataType == "Kmeans":
        decisionPath = p / 'Kmeans'
    
    if dataSet == "NetFlow":
        decisionPath = decisionPath / 'NetFlow'
    elif dataSet == "Telemetry":
        decisionPath = decisionPath / 'Telemetry'

    if attackDate == "17.03.23":
        fileString = "1703"
        thresholdDate = "08.03.23"
        q = decisionPath /'Attack0803' 
    elif attackDate == "24.03.23":
        fileString = "2403"
        thresholdDate = "17.03.23"
        q = decisionPath /'Attack1703'
    if dataType == "RandomForest" or y_field == "Xmas":
        if interval != 0:
            thresholdFile = str(decisionPath) + "/Attack"+ fileString +  "/MinMax/MaxF1."+ str(y_field) +"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".csv"
        else:
            thresholdFile = str(decisionPath) + "/Attack"+ fileString +  "/MinMax/MaxF1."+ str(y_field) +".attack."+str(attackDate)+ ".csv"
    else:
        if interval != 0:
            thresholdFile = str(q) + "/MinMax/MaxF1."+ str(y_field) +"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(thresholdDate)+ ".csv"
        else:
            thresholdFile = str(q) + "/MinMax/MaxF1."+ str(y_field) +".attack."+str(thresholdDate)+ ".csv"
    
    data = pd.read_csv(thresholdFile)
    systemIds = data["SystemId"].values
    precisionScores = pd.to_numeric(data["PPV"],errors='coerce')
    totals = pd.to_numeric(data["total"],errors='coerce')
    
    if systemId not in systemIds:
        return mean(precisionScores)/mean(totals)
    
    precision = data.loc[data["SystemId"] == systemId, "PPV"].item()
    total = data.loc[data["SystemId"] == systemId, "total"].item()
    print(precision/total)
    return precision/total

#getThreshold("dstEntropy", "ifi2-gw5", timedelta(minutes=5), "Entropy", "NetFlow", "17.03.23")