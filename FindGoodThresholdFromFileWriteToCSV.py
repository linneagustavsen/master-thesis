

from ast import literal_eval
from datetime import datetime, timedelta
from pathlib import Path
import numpy as np
import pandas as pd


def findGoodThresholdFromFile(y_field, dataSet, dataType, systems, interval, attackDate):
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

    if attackDate == "08.03.23":
        fileString = "0803"
        q = decisionPath /'Attack0803'
    elif attackDate == "17.03.23":
        fileString = "1703"
        q = decisionPath /'Attack1703' 
    elif attackDate == "24.03.23":
        fileString = "2403"
        q = decisionPath /'Attack2403'

    if not(dataType == "RandomForest" or dataType == "Kmeans" or y_field == "Xmas"):
        if interval != 0:
            if not q.exists():
                q.mkdir(parents=True)
            f = open(str(q) + "/MinMax/MaxTPR."+ str(y_field) +"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".csv", "a")
            f.write("SystemId,threshold,maxTPR,PPV,total")
            f1 = open(str(q) + "/MinMax/MaxF1."+ str(y_field) +"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".csv", "a")
            f1.write("SystemId,threshold,maxF1,PPV,total")
        else:
            if not q.exists():
                q.mkdir(parents=True)
            f = open(str(q) + "/MinMax/MaxTPR."+ str(y_field) +".attack."+str(attackDate)+ ".csv", "a")
            f.write("SystemId,threshold,maxTPR,PPV,total")
            f1 = open(str(q) + "/MinMax/MaxF1."+ str(y_field) +".attack."+str(attackDate)+ ".csv", "a")
            f1.write("SystemId,threshold,maxF1,PPV,total")

        for systemId in systems:
            print(systemId)
            if interval != 0:
                dataFile = str(q) + "/" + str(y_field) +"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv"
                if not Path(dataFile).exists():
                    continue
            else:
                dataFile = str(q) + "/" + str(y_field) +".attack."+str(attackDate)+ "."+str(systemId)+ ".csv"
                if not Path(dataFile).exists():
                    continue

            data = pd.read_csv(dataFile)
            thresholds = pd.to_numeric(data["Threshold"],errors='coerce')
            tpr = pd.to_numeric(data["TPR"],errors='coerce')
            tp = pd.to_numeric(data["TP"], errors='coerce')
            fp = pd.to_numeric(data["FP"], errors='coerce')
            tn = pd.to_numeric(data["TN"], errors='coerce')
            fn = pd.to_numeric(data["FN"], errors='coerce')
            ppv = pd.to_numeric(data["PPV"],errors='coerce')
            f1_scores = pd.to_numeric(data["F1"],errors='coerce')

            max_tpr = 0
            index_tpr = 0
            max_f1 = 0
            index_f1 = 0
            counter = 0

            for i in range(len(thresholds)):
                if tp[i] == 0:
                    continue

                if tpr[i] >= max_tpr and tpr[i] != np.nan:
                    max_tpr = tpr[i]
                    index_tpr = i

                if f1_scores[i] >= max_f1 and f1_scores[i] != np.nan:
                    max_f1 = f1_scores[i]
                    index_f1 = i


                counter += 1

            if counter == 0:
                continue
            total_tpr = tp[index_tpr] + fp[index_tpr] + fn[index_tpr] + tn[index_tpr]
            total_f1 = tp[index_f1] + fp[index_f1] + fn[index_f1] + tn[index_f1]
            f.write("\n" + str(systemId) + "," + str(thresholds[index_tpr]) + "," + str(tpr[index_tpr])+ "," +str(ppv[index_tpr]) + "," + str(total_tpr))
            f1.write("\n" + str(systemId) + "," + str(thresholds[index_f1]) + "," + str(f1_scores[index_f1])+ "," +str(ppv[index_f1]) + "," + str(total_f1))
            
        f.close()
        f1.close()
    else:
        if interval != 0:
            if not q.exists():
                q.mkdir(parents=True)
            f = open(str(q) + "/MinMax/MaxTPR."+ str(y_field) +"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".csv", "a")
            f.write("SystemId,PPV,total")
            f1 = open(str(q) + "/MinMax/MaxF1."+ str(y_field) +"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ ".csv", "a")
            f1.write("SystemId,PPV,total")
        else:
            if not q.exists():
                q.mkdir(parents=True)
            f = open(str(q) + "/MinMax/MaxTPR."+ str(y_field) +".attack."+str(attackDate)+ ".csv", "a")
            f.write("SystemId,PPV,total")
            f1 = open(str(q) + "/MinMax/MaxF1."+ str(y_field) +".attack."+str(attackDate)+ ".csv", "a")
            f1.write("SystemId,PPV,total")

        for systemId in systems:
            if dataType == "RandomForest":
                if y_field != "FieldsNoIP" and y_field != "CombinedNoIP":
                    if interval != 0:
                        dataFile = "Calculations"+fileString+"/"+dataType+ "/"+dataSet+"/Score." + str(y_field) +"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv"
                        if not Path(dataFile).exists():
                            continue
                    else:
                        dataFile = "Calculations"+fileString+"/"+dataType+ "/"+dataSet+"/Score." + str(y_field) +".attack."+str(attackDate)+ "."+str(systemId)+ ".csv"
                        if not Path(dataFile).exists():
                            continue
                else:
                    if interval != 0:
                        dataFile = "Calculations"+fileString+"/"+dataType+ "/"+dataSet+"/ScoreNoIP." + str(y_field.replace("NoIP", "")) +"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv"
                        if not Path(dataFile).exists():
                            continue
                    else:
                        dataFile = "Calculations"+fileString+"/"+dataType+ "/"+dataSet+"/ScoreNoIP." + str(y_field.replace("NoIP", "")) +".attack."+str(attackDate)+ "."+str(systemId)+ ".csv"
                        if not Path(dataFile).exists():
                            continue
                data = pd.read_csv(dataFile)
                if data.empty:
                    continue
                confusion_matrix = data["confusion_matrix"].values
                confusion_matrix = literal_eval(str(confusion_matrix).replace("['", "").replace("']", "").replace("' '", ",").replace(" ", ",").replace(",,,,,", ",").replace(",,,,", ",").replace(",,,", ",").replace(",,", ",").replace("[,", "["))

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
                if truePositives != 0 or falsePositives != 0:
                    ppv = truePositives/(truePositives+falsePositives)
                else:
                    continue
                total = truePositives + falsePositives + falseNegatives + trueNegatives
                f.write("\n" + str(systemId) + "," +str(ppv)+ ","+ str(total))
                f1.write("\n" + str(systemId) + "," +str(ppv)+ ","+ str(total))
                continue
            else:
                if interval != 0:
                    dataFile = "Calculations"+fileString+"/"+dataType+ "/"+dataSet+"/Scores." + str(y_field) +"."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv"
                    if not Path(dataFile).exists():
                        print(dataFile, "does not exist")
                        continue
                else:
                    dataFile = "Calculations"+fileString+"/"+dataType+ "/"+dataSet+"/Scores." + str(y_field) +".attack."+str(attackDate)+ "."+str(systemId)+ ".csv"
                    if not Path(dataFile).exists():
                        print(dataFile, "does not exist")
                        continue
            

            data = pd.read_csv(dataFile)
            if data.empty:
                print("Data is empty")
                print(data)
                continue
            tp = data["TP"][0]
            fp = data["FP"][0]
            tn = data["TN"][0]
            fn = data["FN"][0]

            if tp != 0 or fp != 0:
                ppv = tp/(tp+fp)
            else:
                continue
            total = tp + fp + fn + tn
            f.write("\n" + str(systemId) + "," +str(ppv)+ ","+ str(total))
            f1.write("\n" + str(systemId) + "," +str(ppv)+ ","+ str(total))
            
        f.close()
        f1.close()

        
systems = ["stangnes-gw", "rodbergvn-gw2", "narvik-gw4", "tromso-fh-gw", "tromso-gw5",  "teknobyen-gw1", "narvik-gw3", "hovedbygget-gw",
           "hoytek-gw2", "teknobyen-gw2", "ma2-gw", "bergen-gw3", "narvik-kv-gw",  "trd-gw", "ifi2-gw5", 
            "oslo-gw1"]
attackDates = ["08.03.23", "17.03.23","24.03.23"]
y_fields = ["dstEntropy", "dstEntropyRate","srcEntropy", "srcEntropyRate", "flowEntropy", "flowEntropyRate", "numberOfFlows", "icmpRatio", 
            "icmpPackets", "packetSizeEntropy", "packetSizeEntropyRate", "numberOfPackets", "numberOfBytes", "SYN.dstEntropy", "SYN.srcEntropy", "SYN.flowEntropy"]
intervals = [timedelta(minutes = 5),timedelta(minutes = 10), timedelta(minutes = 15)]
print("NetFlow entropy")
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        for interval in intervals:
            print(interval)
            findGoodThresholdFromFile(y_field, "NetFlow", "Entropy", systems, interval, attackDate)

y_fields= ["entropy_packet_size_ingress","entropy_rate_packet_size_ingress","numberOfPackets_ingress","numberOfBytes_ingress",
           "entropy_packet_size_egress","entropy_rate_packet_size_egress","numberOfPackets_egress","numberOfBytes_egress"]
print("Telemetry entropy")
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        for interval in intervals:
            print(interval)
            findGoodThresholdFromFile(y_field, "Telemetry", "Entropy", systems, interval, attackDate)


y_fields = ["ICMPDstUnreachable"]
intervals = [timedelta(minutes = 5),timedelta(minutes = 10), timedelta(minutes = 15)]
print("NetFlow ICMP dst unreachable")
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        for interval in intervals:
            print(interval)
            findGoodThresholdFromFile(y_field, "NetFlow", "Threshold", systems, interval, attackDate)

y_fields = ["SYN"]
print("NetFlow SYN")
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        findGoodThresholdFromFile(y_field, "NetFlow", "Threshold", systems, 0, attackDate)

y_fields = ["Xmas"]
print("NetFlow Xmas")
attackDate = "24.03.23"
print("\n")
print(attackDate)
for y_field in y_fields:
    print(y_field)
    findGoodThresholdFromFile(y_field, "NetFlow", "Threshold", systems, 0, attackDate)

y_fields = ["TopKFlows"]
print("NetFlow TopKFlows")
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        findGoodThresholdFromFile(y_field, "NetFlow", "TopKFlows", systems, 0, attackDate)

y_fields= ["egress_queue_info__0__cur_buffer_occupancy", "egress_stats__if_1sec_pkts", "egress_stats__if_1sec_octets", "ingress_stats__if_1sec_pkts", "ingress_stats__if_1sec_octets", "MaxVar.egress_queue_info__0__cur_buffer_occupancy", "MaxVar.egress_stats__if_1sec_pkts", "MaxVar.egress_stats__if_1sec_octets", "MaxVar.ingress_stats__if_1sec_pkts", "MaxVar.ingress_stats__if_1sec_octets"]
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        findGoodThresholdFromFile(y_field, "Telemetry", "Threshold", systems, 0, attackDate)

y_fields= ["Fields", "FieldsNoIP"]
attackDate = "24.03.23"
for y_field in y_fields:
    print(y_field)
    findGoodThresholdFromFile(y_field, "NetFlow", "RandomForest", systems, 0, attackDate)

y_fields= ["Entropy", "Combined", "CombinedNoIP"]
attackDate = "24.03.23"
for y_field in y_fields:
    print(y_field)
    for interval in intervals:
        print(interval)
        findGoodThresholdFromFile(y_field, "NetFlow", "RandomForest", systems, interval, attackDate)

y_fields= ["Fields"]
attackDate = "24.03.23"
for y_field in y_fields:
    print(y_field)
    findGoodThresholdFromFile(y_field, "Telemetry", "RandomForest", systems, 0, attackDate)

y_fields= ["Entropy", "Combined"]
attackDate = "24.03.23"
for y_field in y_fields:
    print(y_field)
    for interval in intervals:
        print(interval)
        findGoodThresholdFromFile(y_field, "Telemetry", "RandomForest", systems, interval, attackDate)

y_fields= ["Fields"]
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        findGoodThresholdFromFile(y_field, "NetFlow", "Kmeans", systems, 0, attackDate)

y_fields= ["Entropy", "Combined"]
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        for interval in intervals:
            print(interval)
            findGoodThresholdFromFile(y_field, "NetFlow", "Kmeans", systems, interval, attackDate)

y_fields= ["Fields"]
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        findGoodThresholdFromFile(y_field, "Telemetry", "Kmeans", systems, 0, attackDate)

y_fields= ["Entropy", "Combined"]
for attackDate in attackDates:
    print("\n")
    print(attackDate)
    for y_field in y_fields:
        print(y_field)
        for interval in intervals:
            print(interval)
            findGoodThresholdFromFile(y_field, "Telemetry", "Kmeans", systems, interval, attackDate)

y_fields= ["Entropy"]
attackDate = "17.03.23"
for y_field in y_fields:
    print(y_field)
    for interval in intervals:
        print(interval)
        findGoodThresholdFromFile(y_field, "Telemetry", "Kmeans", systems, interval, attackDate)