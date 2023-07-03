from datetime import timedelta
from pathlib import Path
import re

import numpy as np

def recalculateRanking(metric, interval, attackDate):
    if attackDate == "08.03.23":
        fileString = "0803"
    elif attackDate == "17.03.23":
        fileString = "1703"
    elif attackDate == "24.03.23":
        fileString = "2403"
        
    if interval == timedelta(minutes = 5):
        windowSize = "5min"
    elif interval == timedelta(minutes = 10):
        windowSize = "10min"
    elif interval == timedelta(minutes = 15):
        windowSize = "15min"
    p = Path('Detections' + fileString +"_"+ windowSize +"_"+ metric)
    routers = {"trd-gw": "AR1",
                   "ifi2-gw5": "AR2",
                   "bergen-gw3": "AR3",
                   "tromso-gw5": "AR4",
                   "teknobyen-gw1": "VR",  
                   "hoytek-gw2": "CR3"}
    fileAttackType = str(p) + "/Correlation/RankingAttackType.csv"
    fileDeviationScore = str(p) + "/Correlation/RankingDeviationScore.csv"
    # Open the file in read mode
    """majority_fp = 0
    majority_tp = 0
    one_in_it_fp = 0
    one_in_it_tp = 0
    majority_weight_fp = 0
    majority_weight_tp = 0
    newRanking = False
    ranking = []
    with open(fileAttackType, 'r') as file:
    # Read all lines of the file
        lines = file.readlines()
        lineCounter = 0
        # Iterate over each line
        for line in lines:
            # Split the line using a comma not followed by a space
            values = re.split(r',(?!\s)', line.strip())
            if values == ['']:
                ranking = sorted(ranking, key=lambda x: x["Weight"], reverse=True)
                rankingFile = open("Calculations/Correlation/New.RankingWeight.csv", "a")
                rankingFile.write("Position,sTime,eTime,Gateways,Deviation_score,Attack_type,Real_labels")
                alerts = list(ranking)
                position = 0
                writeLine = ""
                for alert in alerts:
                    writeLine += "\n"
                    writeLine += str(position) + ","
                    writeLine += alert['sTime'] + ","
                    writeLine += alert['eTime'] + ","
                    newGateways = ""
                    for gateway in alert['Gateways']:
                        newGateways += gateway + "; "
                    writeLine += newGateways + ","

                    deviationScores = ""
                    if "nan" in alert['Deviation_score']:
                        deviationScores += "Mean: Not defined"
                    else:
                        deviationScore = eval(deviation_score)
                        deviationScores += "Mean: " + "%.5f"%deviationScore["mean"] + "; "
                        if "standard_deviation" in deviationScores:
                            deviationScores += "Standard deviation: " + "%.5f"%deviationScore["standard_deviation"]

                    writeLine += deviationScores + ","

                    attacks = ""
                    for attack in alert['Attack_types']:
                        print(attack)
                        if attack == "":
                            attacks += "No type" + ": "+ "%.5f"%alert['Attack_types'][attack] + "; "
                        else:
                            attacks += attack + ": "+ "%.5f"%alert['Attack_types'][attack] + "; "

                    
                    writeLine += attacks + ","


                    real_labels = sorted(alert['Real_labels'].items(), key=lambda x:x[1], reverse=True)
                    labels = ""
                    for label in real_labels:
                        labels += label[0].replace("'", "") + ": "+ str(label[1]) + "; "
                    writeLine += labels

                    real_labels = alert["Real_labels"]
                    weight =alert["Weight"] 
                    if int(position) < 10:
                        if '1' not in real_labels:
                            majority_fp += 1
                            one_in_it_fp += 1
                            majority_weight_fp += weight
                        elif '0' not in real_labels:
                            majority_tp += 1
                            one_in_it_tp += 1
                            majority_weight_tp += weight
                        else:
                            one_in_it_tp += 1
                            if real_labels['0'] > real_labels['1']:
                                majority_fp += 1
                                majority_weight_fp += weight
                            elif real_labels['0'] < real_labels['1']:
                                majority_tp += 1
                                majority_weight_tp += weight
                    
                    position += 1
                writeLine += "\n"
                writeLine += "\n"
                rankingFile.write(writeLine)
                rankingFile.close()

                lineCounter += 1
                newRanking = False
                continue
            weight = 0   
            # Access the values in each column by their indices
            position = values[0]
            s_time = values[1]
            e_time = values[2]
            gateways = values[3]
            deviation_score = values[4]
            attack_type = values[5]
            real_labels = values[6]

            # Perform your desired changes on each line
            # For example, print the values of each column
            '''print(f"Position: {position}")
            print(f"Start Time: {s_time}")
            print(f"End Time: {e_time}")
            print(f"Gateways: {gateways}")
            print(f"Deviation Score: {deviation_score}")
            print(f"Attack Type: {attack_type}")
            print(f"Real Labels: {real_labels}")
            print()'''

            alert = {
                    "sTime": s_time,
                    "eTime": e_time
            }
            
            newValues = [position, s_time, e_time]
            if values == ['Position', 'sTime', 'eTime', 'Gateways', 'Deviation_score', 'Attack_type', 'Real_labels']:
                lineCounter+=1
                ranking = []
                continue
            
            newerGateways = list(gateways.replace("[", "").replace("]", "").split("', '"))
            gatewayList = []
            newGateways = ""
            # Perform your modifications on the line here
            for gateway in newerGateways:
                newGateways += routers[gateway.replace("'", "")] + "; "
                gatewayList.append(routers[gateway.replace("'", "")])
            newValues.append(newGateways)
            alert["Gateways"] = gatewayList
        

            attack_type = eval(attack_type)
            attack_type = sorted(attack_type.items(), key=lambda x:x[1], reverse=True)
            attacks = ""
            attackTypeDict = {}
            for attack in attack_type:
                if attack[0] == "":
                    attacks += "No type" + ": "+ "%.5f"%attack[1] + "; "
                else:
                    attacks += attack[0].replace("'", "") + ": "+ "%.5f"%attack[1] + "; "
                attackTypeDict[attack[0].replace("'", "")] = attack[1]
                weight += attack[1]
            newValues.append(attacks)
            alert["Attack_types"]= attackTypeDict

            print(deviation_score)
            deviationScores = ""
            if "nan" in deviation_score:
                deviationScores += "Mean: Not defined"
                alert["Deviation_score"] = {"mean": 0}
            else:
                deviationScore = eval(deviation_score)
                alertDict = {"mean": deviationScore["mean"]}
                deviationScores += "Mean: " + "%.5f"%deviationScore["mean"] + "; "
                if "standard_deviation" in deviationScores:
                    deviationScores += "Standard deviation: " + "%.5f"%deviationScore["standard_deviation"]
                    alertDict["standard_deviation"] = deviationScore["standard_deviation"]
                alert["Deviation_score"] = alertDict

            newValues.append(deviationScores)

            real_labels = eval(real_labels)
            alert["Real_labels"] = real_labels
            alert["Weight"] = weight
            '''if int(position) < 10:
                if '1' not in real_labels:
                    majority_fp += 1
                    one_in_it_fp += 1
                    majority_weight_fp += weight
                elif '0' not in real_labels:
                    majority_tp += 1
                    one_in_it_tp += 1
                    majority_weight_tp += weight
                else:
                    one_in_it_tp += 1
                    if real_labels['0'] > real_labels['1']:
                        majority_fp += 1
                        majority_weight_fp += weight
                    elif real_labels['0'] < real_labels['1']:
                        majority_tp += 1
                        majority_weight_tp += weight'''
            real_labels = sorted(real_labels.items(), key=lambda x:x[1], reverse=True)
            labels = ""
            for label in real_labels:
                labels += label[0].replace("'", "") + ": "+ str(label[1]) + "; "

            newValues.append(labels)

            ranking.append(alert)

            '''with open('Calculations/Correlation/New.RankingAttackType.csv', 'a') as output_file:
                output_file.write(','.join(newValues))
                output_file.write("\n")'''
            
            lineCounter+=1
    precision_majority = majority_tp/(majority_tp+majority_fp)
    precision_one_in_it = one_in_it_tp/(one_in_it_tp+one_in_it_fp)
    precision_weighted = majority_weight_tp/(majority_weight_tp+ majority_weight_fp)
    with open('Calculations/Correlation/New.NumberOfAlertsRankingWeight.csv', 'a') as output_file:
        output_file.write("majority,1_in_it,weighted")
        output_file.write("\n" + str(precision_majority) + "," + str(precision_one_in_it) + "," + str(precision_weighted))
        output_file.write("\n")
"""

    majority_fp = 0
    majority_tp = 0
    one_in_it_fp = 0
    one_in_it_tp = 0
    majority_weight_fp = 0
    majority_weight_tp = 0
    with open(fileAttackType, 'r') as file:
    # Read all lines of the file
        lines = file.readlines()
        lineCounter = 0
        # Iterate over each line
        for line in lines:
            # Split the line using a comma not followed by a space
            values = re.split(r',(?!\s)', line.strip())
            if values == ['']:
                ranking = sorted(ranking, key=lambda x: x["Deviation_score"], reverse=True)
                rankingFile = open("Calculations/Correlation/New.RankingStdDev.csv", "a")
                rankingFile.write("Position,sTime,eTime,Gateways,Deviation_score,Attack_type,Real_labels")
                alerts = list(ranking)
                position = 0
                writeLine = ""
                for alert in alerts:
                    writeLine += "\n"
                    writeLine += str(position) + ","
                    writeLine += alert['sTime'] + ","
                    writeLine += alert['eTime'] + ","
                    newGateways = ""
                    for gateway in alert['Gateways']:
                        newGateways += gateway + "; "
                    writeLine += newGateways + ","

                    deviationScores = ""
                    if alert["Deviation_score"] == 0:
                        deviationScores += "Not defined"
                    else:
                        deviationScores +=  "%.5f"%alert["Deviation_score"]

                    writeLine += deviationScores + ","

                    attacks = ""
                    for attack in alert['Attack_types']:
                        if attack == "":
                            attacks += "No type" + ": "+ "%.5f"%alert['Attack_types'][attack] + "; "
                        else:
                            attacks += attack + ": "+ "%.5f"%alert['Attack_types'][attack] + "; "

                    
                    writeLine += attacks + ","


                    real_labels = sorted(alert['Real_labels'].items(), key=lambda x:x[1], reverse=True)
                    labels = ""
                    for label in real_labels:
                        labels += label[0].replace("'", "") + ": "+ str(label[1]) + "; "
                    writeLine += labels

                    real_labels = alert["Real_labels"]
                    weight =alert["Weight"] 
                    if int(position) < 10:
                        if '1' not in real_labels:
                            majority_fp += 1
                            one_in_it_fp += 1
                            majority_weight_fp += weight
                        elif '0' not in real_labels:
                            majority_tp += 1
                            one_in_it_tp += 1
                            majority_weight_tp += weight
                        else:
                            one_in_it_tp += 1
                            if real_labels['0'] > real_labels['1']:
                                majority_fp += 1
                                majority_weight_fp += weight
                            elif real_labels['0'] < real_labels['1']:
                                majority_tp += 1
                                majority_weight_tp += weight
                    
                    position += 1
                writeLine += "\n"
                writeLine += "\n"
                rankingFile.write(writeLine)
                rankingFile.close()

                lineCounter += 1
                newRanking = False
                continue
            weight = 0   
            # Access the values in each column by their indices
            position = values[0]
            s_time = values[1]
            e_time = values[2]
            gateways = values[3]
            deviation_score = values[4]
            attack_type = values[5]
            real_labels = values[6]

            # Perform your desired changes on each line
            # For example, print the values of each column
            '''print(f"Position: {position}")
            print(f"Start Time: {s_time}")
            print(f"End Time: {e_time}")
            print(f"Gateways: {gateways}")
            print(f"Deviation Score: {deviation_score}")
            print(f"Attack Type: {attack_type}")
            print(f"Real Labels: {real_labels}")
            print()'''

            alert = {
                    "sTime": s_time,
                    "eTime": e_time
            }
            
            newValues = [position, s_time, e_time]
            if values == ['Position', 'sTime', 'eTime', 'Gateways', 'Deviation_score', 'Attack_type', 'Real_labels']:
                lineCounter+=1
                ranking = []
                continue
            
            newerGateways = list(gateways.replace("[", "").replace("]", "").split("', '"))
            gatewayList = []
            newGateways = ""
            # Perform your modifications on the line here
            for gateway in newerGateways:
                newGateways += routers[gateway.replace("'", "")] + "; "
                gatewayList.append(routers[gateway.replace("'", "")])
            newValues.append(newGateways)
            alert["Gateways"] = gatewayList
        

            attack_type = eval(attack_type)
            attack_type = sorted(attack_type.items(), key=lambda x:x[1], reverse=True)
            attacks = ""
            attackTypeDict = {}
            for attack in attack_type:
                if attack[0] == "":
                    attacks += "No type" + ": "+ "%.5f"%attack[1] + "; "
                else:
                    attacks += attack[0].replace("'", "") + ": "+ "%.5f"%attack[1] + "; "
                attackTypeDict[attack[0].replace("'", "")] = attack[1]
                weight += attack[1]
            newValues.append(attacks)
            alert["Attack_types"]= attackTypeDict


            deviationScores = ""
            if "nan" in deviation_score:
                deviationScores += "Not defined"
                alert["Deviation_score"] = 0
                print("It is nan")
            else:
                deviationScore = eval(deviation_score)
                
                deviationScores +=  "%.5f"%deviationScore["mean"]
                if "standard_deviation" in deviationScore:
                    alert["Deviation_score"] = deviationScore["mean"]/deviationScore["standard_deviation"]
                    #deviationScores += "Standard deviation: " + "%.5f"%deviationScore["standard_deviation"]
                    #alertDict["standard_deviation"] = deviationScore["standard_deviation"]
                else:
                    alert["Deviation_score"] = deviationScore["mean"]
                    print(deviationScore)
                    print("no stdev")


            newValues.append(deviationScores)

            real_labels = eval(real_labels)
            alert["Real_labels"] = real_labels
            alert["Weight"] = weight
            '''if int(position) < 10:
                if '1' not in real_labels:
                    majority_fp += 1
                    one_in_it_fp += 1
                    majority_weight_fp += weight
                elif '0' not in real_labels:
                    majority_tp += 1
                    one_in_it_tp += 1
                    majority_weight_tp += weight
                else:
                    one_in_it_tp += 1
                    if real_labels['0'] > real_labels['1']:
                        majority_fp += 1
                        majority_weight_fp += weight
                    elif real_labels['0'] < real_labels['1']:
                        majority_tp += 1
                        majority_weight_tp += weight'''
            real_labels = sorted(real_labels.items(), key=lambda x:x[1], reverse=True)
            labels = ""
            for label in real_labels:
                labels += label[0].replace("'", "") + ": "+ str(label[1]) + "; "

            newValues.append(labels)

            ranking.append(alert)

            '''with open('Calculations/Correlation/New.RankingAttackType.csv', 'a') as output_file:
                output_file.write(','.join(newValues))
                output_file.write("\n")'''
            
            lineCounter+=1
    precision_majority = majority_tp/(majority_tp+majority_fp)
    precision_one_in_it = one_in_it_tp/(one_in_it_tp+one_in_it_fp)
    precision_weighted = majority_weight_tp/(majority_weight_tp+ majority_weight_fp)
    with open('Calculations/Correlation/New.NumberOfAlertsRankingStDev.csv', 'a') as output_file:
        output_file.write("majority,1_in_it,weighted")
        output_file.write("\n" + str(precision_majority) + "," + str(precision_one_in_it) + "," + str(precision_weighted))
        output_file.write("\n")
        output_file.write("\n")
    
recalculateRanking("F1", timedelta(minutes=15), "24.03.23")