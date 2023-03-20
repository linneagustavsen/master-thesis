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

def weeklyMetricCalculation(silkFiles):
    #Open file to write alerts to
    calculations = open("NetFlow/Entropy/Calculations/WeeklyMetrics.csv", "a")
    
    #Write the column titles to the files
    calculations.write("Week,srcEntropy,srcEntropyRate,dstEntropy,dstEntropyRate,flowEntropy,flowEntropyRate,numberOfFlows,icmpRatio,icmpPackets")
    
    ipSrcArray = []
    ipSrcRateArray = []

    ipDstArray = []
    ipDstRateArray = []

    flowArray = []
    flowRateArray = []

    numberOfFlows = []

    icmpRatioArray = []
    icmpPacketsArray = []
    #Instantiate counter variable
    i = 0
    print("Started on the silk files")
    #Loop through all the flow records in the input file
    for silkFile in silkFiles:
        
        # Open a silk flow file for reading
        infile = silkfile_open(silkFile, READ)

        #Instantiate empty arrays for the calculated values
        records = []
        print("Start on silk file", i)

        #Find the probability distribution based on how many packets there is in each source flow in this time interval
        PiSIP, ns = ipSourceDistribution(infile)
        #Calculate the generalized entropy of this distribution
        entropySip = generalizedEntropy(10,PiSIP)
        ipSrcArray.append(entropySip)
        #Calculate the generalized entropy rate of this distribution
        ipSrcRateArray.append(entropySip/ns)
        print("Finished IP source calculation for silk file", i)

        infile = silkfile_open(silkFile, READ)
        #Find the probability distribution based on how many packets there is in each destination flow in this time interval
        PiDIP, nd = ipDestinationDistribution(infile)
        #Calculate the generalized entropy of this distribution
        entropyDip = generalizedEntropy(10,PiDIP)
        ipDstArray.append(entropyDip)
        #Calculate the generalized entropy rate of this distribution
        ipDstRateArray.append(entropyDip/nd)
        print("Finished IP destination calculation for silk file", i)

        infile = silkfile_open(silkFile, READ)
        #Find the probability distribution based on how many packets there is in each bi-directional flow in this time interval
        PiF, nf = flowDistribution(infile)
        #Calculate the generalized entropy of this distribution
        entropyFlow = generalizedEntropy(10, PiF)
        flowArray.append(entropyFlow)
        #Calculate the generalized entropy rate of this distribution
        flowRateArray.append(entropyFlow/nf)
        print("Finished flow calculation for silk file", i)


        #Store the number of bi-directional flows in this time interval
        numberOfFlows.append(nf)

        infile = silkfile_open(silkFile, READ)
        #Find the ratio of ICMP packets in this time interval
        icmpRatio, icmpPackets = icmpDistribution(infile)
        icmpRatioArray.append(icmpRatio)
        icmpPacketsArray.append(icmpPackets)
        print("Finished ICMP calculation for silk file", i)

        print("Finished with silk file", i)
        calculations.write("\n" + str(i+1) + "," + str(ipSrcArray[i]) + "," + str(ipSrcRateArray[i]) + "," + str(ipDstArray[i]) + "," + str(ipDstRateArray[i]) + "," + str(flowArray[i]) + "," + str(flowRateArray[i]) + "," + str(numberOfFlows[i]) + "," + str(icmpRatioArray[i]) + "," + str(icmpPacketsArray[i]))
        i += 1
        infile.close()
    calculations.close()
     
silkFiles = ["/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week1.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week2.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week3.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week4.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week5.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week6.rw", "/home/linneafg/silk-data/RawDataFromFilter/oslo-gw/week7.rw"]
weeklyMetricCalculation(silkFiles)

