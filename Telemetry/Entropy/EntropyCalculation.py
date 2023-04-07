from datetime import datetime,timedelta
import numpy as np
from HelperFunctions.GetData import *
from HelperFunctions.GeneralizedEntropy import *
from HelperFunctions.Distributions import *
from HelperFunctions.IsAttack import isAttack

'''
    Calculates entropy and writes calculations to file
    Input:  start:      string, indicating the start time of the data to detect on
            stop:       string, indicating the stop time of the data to detect on
            systemId:   string, name of the system to collect and calculate on  
            if_name:    string, interface name, 
            interval:   timedelta object, size of the sliding window which the calculation is made on,
            frequency:  timedelta object, frequency of metric calculation,
            attackDate: string, date of the attack the calculations are made on
'''

def calculationEntropyTelemetry(start, stop, systemId, if_name, interval, frequency, attackDate):
    #Open file to write alerts to
    calculations = open("Calculations/Entropy/Telemetry/Metrics."+ str(int(interval.total_seconds())) +"secInterval.attack."+str(attackDate)+ "."+str(systemId)+ ".csv", "a")
    #Write the column titles to the files
    calculations.write("Time,entropy_packet_size,entropy_rate_packet_size,numberOfPackets,numberOfBytes,real_label")

    #Instantiate empty arrays for the calculated values
    packetSizeArray = []
    packetSizeRateArray = []
    packetNumberArray = []
    bytesArray = []

    #Makes a datetime object of the input start time
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime(stop, '%Y-%m-%d %H:%M:%S')
    
    intervalTime = (stopTime - startTime).total_seconds()/frequency.total_seconds()

    #Loop for every minute in a week
    for i in range(math.ceil(intervalTime)):
        stopTime = startTime + interval
        #Get data for a specified time interval
        df = getData(startTime.strftime("%Y-%m-%dT%H:%M:%SZ"), stopTime.strftime("%Y-%m-%dT%H:%M:%SZ"),systemId, if_name, ["egress_stats__if_1sec_octets","egress_stats__if_1sec_pkts"])
        #If there is no data for this interval we skip the calculations
        if df.empty:
            startTime = startTime + frequency
            continue
        dfEgressBytes = df["egress_stats__if_1sec_octets"].to_numpy()
        dfEgressPackets = df["egress_stats__if_1sec_pkts"].to_numpy()

        #Find the probability distribution based on how big the packets are this time interval
        PiPS,nd = packetSizeDistribution(dfEgressBytes, dfEgressPackets)
        #Calculate the generalized entropy of this distribution
        entropyPacketSize = generalizedEntropy(10, PiPS)
        packetSizeArray.append(entropyPacketSize)

        #Calculate the generalized entropy rate of this distribution
        entropyRatePacketSize = entropyPacketSize/nd
        packetSizeRateArray.append(entropyRatePacketSize)

        #Store the number of packets and bytes this time interval
        packetNumberArray.append(sum(dfEgressPackets["_value"].to_numpy()))
        bytesArray.append(sum(dfEgressBytes["_value"].to_numpy()))

        #If there is not enough stored values to compare with we skip the detection
        calculations.write("\n" + str(startTime) + str(packetSizeArray[i]) + "," + str(packetSizeRateArray[i])
                               + "," + str(packetNumberArray[i]) + "," + str(bytesArray[i]) +  "," + str(int(isAttack(startTime))))
        #Push the start time by the specified frequency
        startTime = startTime + frequency
        i += 1

    calculations.close()
'''
start = "2022-09-21 01:00:00"
stop = "2022-09-22 00:00:00"
systemId = "trd-gw"
if_name = "xe-0/1/0"
interval = timedelta(minutes = 5)
frequency = timedelta(minutes = 1)
attackDate = "21.09"
calculationEntropyTelemetry(start, stop, systemId, if_name, interval, frequency, attackDate)'''
