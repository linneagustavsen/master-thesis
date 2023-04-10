from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *

'''
    Calculates entropy and other metrics and write them to file. Also checks if the flow is an attack flow
    Input:  silkFile:   string, file with flow records sorted on time, 
            week:       int, what week number this calculation is for
'''
def weeklyMetricCalculation(silkFile, week):
    #Open file to write alerts to
    calculations = open("NetFlow/Entropy/Calculations/WeeklyDIP.csv", "a")
    
    #Write the column titles to the files
    calculations.write("Week,dstEntropy")

    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    numberOfPacketsPerDIP ={}
    #A variable to keep track of the total amount of packets in this time interval
    sumOfPacketsDIP = 0
    #Loop through each flow record in the time interval
    for rec in infile:
        #If the current flow has the same source IP as a previous flow the number of packets is added to the record of that source IP
        #If it has not been encountered before it is added to the dictionary
        if rec.dip in numberOfPacketsPerDIP:
            numberOfPacketsPerDIP[rec.dip] += rec.packets
        else:
            numberOfPacketsPerDIP[rec.dip] = rec.packets
        sumOfPacketsDIP += rec.packets

    PiDIP = []

    infile.close()
    infile = silkfile_open(silkFile, READ)
    #Loop through each flow record in the time interval
    for rec in infile:
        PiDIP.append(numberOfPacketsPerDIP[rec.dip]/sumOfPacketsDIP)

    #Calculate the generalized entropy of this distribution
    entropyDip = generalizedEntropy(10,PiDIP)

    calculations.write("\n" + str(week) + "," + str(entropyDip))

    infile.close()
    calculations.close()
     
silkFiles = ["/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week1.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week2.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week3.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week4.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week5.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week6.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week7.rw"]
weeklyMetricCalculation(silkFiles[2], 3)

