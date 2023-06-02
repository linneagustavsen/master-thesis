from datetime import timedelta
from pathlib import Path
from numpy import mean

import pandas as pd


def getThreshold(y_field, systemId, interval, dataType, dataSet, attackDate):
    p = Path('ThresholdDecision')
    
    if dataType == "Entropy":
        decisionPath = p / 'Entropy'
    elif dataType == "Threshold":
        decisionPath = p / 'Threshold'
    elif dataType == "TopKFlows":
        decisionPath = p / 'TopKFlows'
    
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

    if interval != 0:
        thresholdFile = str(q) + "/MinMax/MaxTPR."+ str(y_field) +"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(thresholdDate)+ ".csv"
    else:
        thresholdFile = str(q) + "/MinMax/MaxTPR."+ str(y_field) +".attack."+str(thresholdDate)+ ".csv"
    
    data = pd.read_csv(thresholdFile)
    systemIds = data["SystemId"].values
    thresholds = pd.to_numeric(data["threshold"],errors='coerce')

    if systemId not in systemIds:
        print("There is no threshold for this router")
        path = Path('ThresholdDecision')
        if dataSet == "NetFlow":
            if dataType == "Entropy":
                decision = path / 'Entropy'
            elif dataType == "Threshold":
                decision = path / 'Threshold'
            elif dataType == "TopKFlows":
                print("The data type is top k flows")
                return mean(thresholds)
            
            decision = decision / 'Telemetry'
            
            if attackDate == "17.03.23":
                fileString = "1703"
                thresholdDate = "08.03.23"
                telemetryPath = decision /'Attack0803' 
            elif attackDate == "24.03.23":
                fileString = "2403"
                thresholdDate = "17.03.23"
                telemetryPath = decision /'Attack1703'
            else:
                print("Different attack date")
                return mean(thresholds)
        else:
            print("Not NetFlow")
            return mean(thresholds)
        

        if interval != 0:
            thresholdFileTelemetry = str(telemetryPath) + "/MinMax/MaxTPR."+ str(y_field) +"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(thresholdDate)+ ".csv"
        else:
            thresholdFileTelemetry = str(telemetryPath) + "/MinMax/MaxTPR."+ str(y_field) +".attack."+str(thresholdDate)+ ".csv"
        if not Path(thresholdFileTelemetry).exists():
            print("There is no telemetry file for this field")
            return mean(thresholds)

        data = pd.read_csv(thresholdFileTelemetry)
        systemIds = data["SystemId"].values

        if systemId not in systemIds:
            return mean(thresholds)
        
    threshold = data.loc[data["SystemId"] == systemId, "threshold"].item()
    return threshold

#getThreshold("dstEntropy", "ifi2-gw5", timedelta(minutes=5), "Entropy", "NetFlow", "17.03.23")