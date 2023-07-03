
import json
import pandas as pd
from silk import *
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *
from datetime import datetime
from HelperFunctions.IsAttack import *
from pathlib import Path
import time

from HelperFunctionsTelemetry.GetDataTelemetry import getDataBytes, getDataPackets

'''
    Calculates entropy and other metrics and write them to file. Also checks if the flow is an attack flow
    Input:  
            silkFile:   string, file with flow records sorted on time
            start:      string, indicating the start time of the data wanted
            stop:       string, indicating the stop time of the data wanted
            systemId:   string, name of the system to collect and calculate on
            frequency:  timedelta object, frequency of metric calculation
            interval:   timedelta object, size of the sliding window which the calculation is made on
            attackDate: string, date of the attack the calculations are made on
'''
def findBestRocScore(start, stop, systemId, frequencies, intervals, windowSizes, alphas):
    #Open files to write alerts to
    p = Path('Calculations')
    q = p / 'Entropy' / 'NetFlow'
    if not q.exists():
        q.mkdir(parents=True, exist_ok=False)
    #Open file to write alerts to
    auc_scores_roc = {
        "Entropy of ingress packet sizes":{},
        "Entropy of egress packet sizes":{},

        "Entropy rate of ingress packet sizes":{},
        "Entropy rate of egress packet sizes":{},

        "Number of ingress packets":{},
        "Number of egress packets":{},

        "Number of ingress bytes":{},
        "Number of egress bytes":{},
    }
    auc_scores_pr = {
        "Entropy of ingress packet sizes":{},
        "Entropy of egress packet sizes":{},

        "Entropy rate of ingress packet sizes":{},
        "Entropy rate of egress packet sizes":{},

        "Number of ingress packets":{},
        "Number of egress packets":{},

        "Number of ingress bytes":{},
        "Number of egress bytes":{},
    }

    #Makes datetime objects of the input times
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    for interval in intervals:
        startElapsedTimeInterval = time.time()
        for frequency in frequencies:
            print("Interval:", interval)
            print("Frequency:", frequency)
            startElapsedTimeFrequency = time.time()
            #Instantiate empty arrays for the calculated values
            packetSize_ingress  = []
            packetSize_egress  = []
            packetSize_r_ingress  = []
            packetSize_r_egress  = []

            packets_ingress  = []
            packets_egress  = []
            bytes_ingress  = []
            bytes_egress  = []
            #Instantiate variables
            labels = []

            #Makes datetime objects of the input times
            startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
            stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
            
            intervalTime = (stopTime - startTime).total_seconds()/frequency.total_seconds()
            j = 0
            #Loop for every minute in a week
            for i in range(math.ceil(intervalTime)):
                stopTime = startTime + interval
                #Get data for a specified time interval
                df_bytes_ingress = getDataBytes(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), "april", systemId, "in")
                df_bytes_egress = getDataBytes(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), "april", systemId, "out")
                df_packets_ingress = getDataPackets(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), "april", systemId, "in")
                df_packets_egress = getDataPackets(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"), "april", systemId, "out")
                #If there is no data for this interval we skip the calculations
                if df_bytes_ingress.empty or df_packets_ingress.empty or df_bytes_egress.empty or df_packets_egress.empty:
                    startTime = startTime + frequency
                    continue
                df_bytes_ingress = df_bytes_ingress["bytes"].to_numpy()
                df_packets_ingress = df_packets_ingress["packets"].to_numpy()
                df_bytes_egress = df_bytes_egress["bytes"].to_numpy()
                df_packets_egress = df_packets_egress["packets"].to_numpy()


                #Find the probability distribution based on how big the packets are this time interval
                PiPS_ingress,nps_ingress = packetSizeDistribution(df_bytes_ingress, df_packets_ingress)
            
                
                #Find the probability distribution based on how big the packets are this time interval
                PiPS_egress,nps_egress = packetSizeDistribution(df_bytes_egress, df_packets_egress)

                currentPacketSizeArray_ingress = []
                currentPacketSizeArray_egress = []

                currentPacketSizeRateArray_ingress = []
                currentPacketSizeRateArray_egress = []
                for alpha in alphas:
                    #Calculate the generalized entropy of this distribution
                    entropyPacketSize_ingress = generalizedEntropy(alpha, PiPS_ingress)

                    #Calculate the generalized entropy of this distribution
                    entropyPacketSize_egress = generalizedEntropy(alpha,PiPS_egress)

                    currentPacketSizeArray_ingress.append(entropyPacketSize_ingress)
                    currentPacketSizeArray_egress.append(entropyPacketSize_egress)
                    currentPacketSizeRateArray_ingress.append(entropyPacketSize_ingress/nps_ingress)
                    currentPacketSizeRateArray_egress.append(entropyPacketSize_egress/nps_egress)

                packetSize_ingress.append(currentPacketSizeArray_ingress)
                packetSize_egress.append(currentPacketSizeArray_egress)
                packetSize_r_ingress.append(currentPacketSizeRateArray_ingress)
                packetSize_r_egress.append(currentPacketSizeRateArray_egress)

                #Store the number of packets and bytes this time interval
                packets_ingress.append(sum(df_packets_ingress))
                bytes_ingress.append(sum(df_bytes_ingress))

                packets_egress.append(sum(df_packets_egress))
                bytes_egress.append(sum(df_bytes_egress))
            
                if j == 0:
                    sTime = startTime
                else:
                    sTime =stopTime - frequency
                label = int(isAttack(sTime, stopTime))
                labels.append(label)
                
                startTime = startTime + frequency
                j += 1
                
            packetSize_ingress = np.array(packetSize_ingress)
            packetSize_egress = np.array(packetSize_egress)
            packetSize_r_ingress = np.array(packetSize_r_ingress)
            packetSize_r_egress = np.array(packetSize_r_egress)
            packets_ingress = np.array(packets_ingress)
            packets_egress = np.array(packets_egress)
            bytes_ingress = np.array(bytes_ingress)
            bytes_egress = np.array(bytes_egress)


            for windowSize in windowSizes:
                changes_packets_ingress = []
                changes_packets_egress = []
                changes_bytes_ingress = []
                changes_bytes_egress = []
                for i in range(len(labels)):
                    if i >=windowSize:
                        changes_packets_ingress.append(abs(packets_ingress[i] - np.nanmean(packets_ingress[i-windowSize: i-1])))
                        changes_packets_egress.append(abs(packets_egress[i] - np.nanmean(packets_egress[i-windowSize: i-1])))
                        changes_bytes_ingress.append(abs(bytes_ingress[i] - np.nanmean(bytes_ingress[i-windowSize: i-1])))
                        changes_bytes_egress.append(abs(bytes_egress[i] - np.nanmean(bytes_egress[i-windowSize: i-1])))
                    elif i < 2:
                        changes_packets_ingress.append(0)
                        changes_packets_egress.append(0)
                        changes_bytes_ingress.append(0)
                        changes_bytes_egress.append(0)
                    else:
                        changes_packets_ingress.append(abs(packets_ingress[i] - np.nanmean(packets_ingress[0: i-1])))
                        changes_packets_egress.append(abs(packets_egress[i] - np.nanmean(packets_egress[0: i-1])))
                        changes_bytes_ingress.append(abs(bytes_ingress[i] - np.nanmean(bytes_ingress[0: i-1])))
                        changes_bytes_egress.append(abs(bytes_egress[i] - np.nanmean(bytes_egress[0: i-1])))

                auc_roc = roc_auc_score(labels, changes_packets_ingress)
                auc_pr = average_precision_score(labels, changes_packets_ingress)
                auc_scores_roc["Number of ingress packets"][str("Frequency: " + str(int(frequency.total_seconds())) +"sec Interval: "+ str(int(interval.total_seconds()))+ "sec Window size: "+ str(windowSize*int(frequency.total_seconds())) + "sec")] = auc_roc
                auc_scores_pr["Number of ingress packets"][str("Frequency: " + str(int(frequency.total_seconds())) +"sec Interval: "+ str(int(interval.total_seconds()))+ "sec Window size: "+ str(windowSize*int(frequency.total_seconds())) + "sec")] = auc_pr
                
                auc_roc = roc_auc_score(labels, changes_packets_egress)
                auc_pr = average_precision_score(labels, changes_packets_egress)
                auc_scores_roc["Number of egress packets"][str("Frequency: " + str(int(frequency.total_seconds())) +"sec Interval: "+ str(int(interval.total_seconds()))+ "sec Window size: "+ str(windowSize*int(frequency.total_seconds())) + "sec")] = auc_roc
                auc_scores_pr["Number of egress packets"][str("Frequency: " + str(int(frequency.total_seconds())) +"sec Interval: "+ str(int(interval.total_seconds()))+ "sec Window size: "+ str(windowSize))] = auc_pr
                
                auc_roc = roc_auc_score(labels, changes_bytes_ingress)
                auc_pr = average_precision_score(labels, changes_bytes_ingress)
                auc_scores_roc["Number of ingress bytes"][str("Frequency: " + str(int(frequency.total_seconds())) +"sec Interval: "+ str(int(interval.total_seconds()))+ "sec Window size: "+ str(windowSize*int(frequency.total_seconds())) + "sec")] = auc_roc
                auc_scores_pr["Number of ingress bytes"][str("Frequency: " + str(int(frequency.total_seconds())) +"sec Interval: "+ str(int(interval.total_seconds()))+ "sec Window size: "+ str(windowSize*int(frequency.total_seconds())) + "sec")] = auc_pr
                
                auc_roc = roc_auc_score(labels, changes_bytes_egress)
                auc_pr = average_precision_score(labels, changes_bytes_egress)
                auc_scores_roc["Number of egress bytes"][str("Frequency: " + str(int(frequency.total_seconds())) +"sec Interval: "+ str(int(interval.total_seconds()))+ "sec Window size: "+ str(windowSize*int(frequency.total_seconds())) + "sec")] = auc_roc
                auc_scores_pr["Number of egress bytes"][str("Frequency: " + str(int(frequency.total_seconds())) +"sec Interval: "+ str(int(interval.total_seconds()))+ "sec Window size: "+ str(windowSize*int(frequency.total_seconds())) + "sec")] = auc_pr
                for a in range(len(alphas)):
                    alpha = alphas[a]
                    changes_packetSize_ingress = []
                    changes_packetSize_egress = []
                    changes_packetSize_r_ingress  = []
                    changes_packetSize_r_egress = []
                    
                    for i in range(len(labels)):
                        if i >=windowSize:
                            changes_packetSize_ingress.append(abs(packetSize_ingress[i,a] - np.nanmean(packetSize_ingress[i-windowSize: i-1,a])))
                            changes_packetSize_egress.append(abs(packetSize_egress[i,a] - np.nanmean(packetSize_egress[i-windowSize: i-1,a])))
                            changes_packetSize_r_ingress.append(abs(packetSize_r_ingress[i,a] - np.nanmean(packetSize_r_ingress[i-windowSize: i-1,a])))
                            changes_packetSize_r_egress.append(abs(packetSize_r_egress[i,a] - np.nanmean(packetSize_r_egress[i-windowSize: i-1,a])))
                        elif i < 2:
                            changes_packetSize_ingress.append(0)
                            changes_packetSize_egress.append(0)
                            changes_packetSize_r_ingress.append(0)
                            changes_packetSize_r_egress.append(0)
                        else:
                            changes_packetSize_ingress.append(abs(packetSize_ingress[i,a] - np.nanmean(packetSize_ingress[0: i-1,a])))
                            changes_packetSize_egress.append(abs(packetSize_egress[i,a] - np.nanmean(packetSize_egress[0: i-1,a])))
                            changes_packetSize_r_ingress.append(abs(packetSize_r_ingress[i,a] - np.nanmean(packetSize_r_ingress[0: i-1,a])))
                            changes_packetSize_r_egress.append(abs(packetSize_r_egress[i,a] - np.nanmean(packetSize_r_egress[0: i-1,a])))

                    auc_roc = roc_auc_score(labels, changes_packetSize_ingress)
                    auc_pr = average_precision_score(labels, changes_packetSize_ingress)
                    auc_scores_roc["Entropy of ingress packet sizes"][str("Frequency: " + str(int(frequency.total_seconds())) +"sec Interval: "+ str(int(interval.total_seconds()))+ "sec Window size: "+ str(windowSize*int(frequency.total_seconds())) + "sec alpha: "+ str(alpha))] = auc_roc
                    auc_scores_pr["Entropy of ingress packet sizes"][str("Frequency: " + str(int(frequency.total_seconds())) +"sec Interval: "+ str(int(interval.total_seconds()))+ "sec Window size: "+ str(windowSize*int(frequency.total_seconds())) + "sec alpha: "+ str(alpha))] = auc_pr
                    
                    auc_roc = roc_auc_score(labels, changes_packetSize_egress)
                    auc_pr = average_precision_score(labels, changes_packetSize_egress)
                    auc_scores_roc["Entropy of egress packet sizes"][str("Frequency: " + str(int(frequency.total_seconds())) +"sec Interval: "+ str(int(interval.total_seconds()))+ "sec Window size: "+ str(windowSize*int(frequency.total_seconds())) + "sec alpha: "+ str(alpha))] = auc_roc
                    auc_scores_pr["Entropy of egress packet sizes"][str("Frequency: " + str(int(frequency.total_seconds())) +"sec Interval: "+ str(int(interval.total_seconds()))+ "sec Window size: "+ str(windowSize*int(frequency.total_seconds())) + "sec alpha: "+ str(alpha))] = auc_pr
                    

                    auc_roc = roc_auc_score(labels, changes_packetSize_r_ingress)
                    auc_pr = average_precision_score(labels, changes_packetSize_r_ingress)
                    auc_scores_roc["Entropy rate of ingress packet sizes"][str("Frequency: " + str(int(frequency.total_seconds())) +"sec Interval: "+ str(int(interval.total_seconds()))+ "sec Window size: "+ str(windowSize*int(frequency.total_seconds())) + "sec alpha: "+ str(alpha))] = auc_roc
                    auc_scores_pr["Entropy rate of ingress packet sizes"][str("Frequency: " + str(int(frequency.total_seconds())) +"sec Interval: "+ str(int(interval.total_seconds()))+ "sec Window size: "+ str(windowSize*int(frequency.total_seconds())) + "sec alpha: "+ str(alpha))] = auc_pr
                    
                    auc_roc = roc_auc_score(labels, changes_packetSize_r_egress)
                    auc_pr = average_precision_score(labels, changes_packetSize_r_egress)
                    auc_scores_roc["Entropy rate of egress packet sizes"][str("Frequency: " + str(int(frequency.total_seconds())) +"sec Interval: "+ str(int(interval.total_seconds()))+ "sec Window size: "+ str(windowSize*int(frequency.total_seconds())) + "sec alpha: "+ str(alpha))] = auc_roc
                    auc_scores_pr["Entropy rate of egress packet sizes"][str("Frequency: " + str(int(frequency.total_seconds())) +"sec Interval: "+ str(int(interval.total_seconds()))+ "sec Window size: "+ str(windowSize*int(frequency.total_seconds())) + "sec alpha: "+ str(alpha))] = auc_pr
            endElapsedTimeFrequency = time.time()
            print("One frequency takes:", endElapsedTimeFrequency-startElapsedTimeFrequency)
        endElapsedTimeInterval = time.time()
        print("One interval takes:", endElapsedTimeInterval-startElapsedTimeInterval)
    json_file = open("ThresholdDecision/Entropy/Telemetry/AUC_roc.json", "w")
    json.dump(auc_scores_roc,json_file)
    json_file.close()

    json_file = open("ThresholdDecision/Entropy/Telemetry/AUC_pr.json", "w")
    json.dump(auc_scores_pr,json_file)
    json_file.close()