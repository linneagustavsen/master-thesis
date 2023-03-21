'''
How to get the flows in a file format:

    #Filter out all flows from a time period
    rwfilter --start-date=2011/01/03:00 --end-date=2011/01/10:00 --all-destination=/home/linneafg/silk-data/RawDataFromFilter/one-week-2011-01-03_03-10.rw --data-rootdir=/home/linneafg/silk-data/oslo-gw

    #Sorts them by start time
    rwsort --fields=stime --output-path=/home/linneafg/silk-data/RawDataFromFilter/one-week-2011-01-03_03-10-sorted.rw /home/linneafg/silk-data/RawDataFromFilter/one-week-2011-01-03_03-10.rw

'''

from silk import *
from HelperFunctions.Distributions import *
from HelperFunctions.GeneralizedEntropy import *

'''

    Calculates entropy and other metrics and write them to file. Also checks if the flow is an attack flow
    Input:  File with flow records sorted on time, 
            start time as a string, 
            an aggregation interval as a timedelta object, 
            a window size of how far back we should compare the values
'''

def weeklyMetricCalculation(silkFile, week):
    #Open file to write alerts to
    calculations = open("NetFlow/Entropy/Calculations/WeeklyDIP.csv", "a")
    
    #Write the column titles to the files
    #calculations.write("Week,dstEntropy")
    
    
    #Instantiate counter variable
    i = 0
    print("Started on the silk files")
    #Loop through all the flow records in the input file
    
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)

    #Instantiate empty arrays for the calculated values
    
    print("Start on silk file", week)
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
    print(PiDIP[0:10])
    print(len(PiDIP))
    
    #Calculate the generalized entropy of this distribution
    entropyDip = generalizedEntropy(10,PiDIP)
    print("Finished IP destination calculation for silk file", i)

    calculations.write("\n" + str(week) + "," + str(entropyDip))

    i += 1
    infile.close()
    calculations.close()
     
silkFiles = ["/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week1.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week2.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week3.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week4.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week5.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week6.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week7.rw"]
weeklyMetricCalculation(silkFiles[3], 4)

