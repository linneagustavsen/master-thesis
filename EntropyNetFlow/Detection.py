'''

rwfilter --start-date=2011/01/01:10 --end-date=2011/01/01:11 --all-destination=/home/linneafg/silk-data/RawDataFromFilter/one-hour-2010-12-01_10-11.rw --data-rootdir=/home/linneafg/silk-data/oslo-gw

'''

# Import the PySiLK bindings
from silk import *
from Distributions import *
from GeneralizedEntropy import *
from ICMPRatio import *
from datetime import datetime,timedelta
from MakePlot import *
import time
import numpy as np


# Main function
def detection(silkFile):
    srcEntropyFile = open("EntropyNetFlow/Detections/SourceIPEntropy.txt", "a")
    srcEntropyRateFile = open("EntropyNetFlow/Detections/SourceIPEntropyRate.txt", "a")
    dstEntropyFile = open("EntropyNetFlow/Detections/DestinationIPEntropy.txt", "a")
    dstEntropyRateFile = open("EntropyNetFlow/Detections/DestinationIPEntropyRate.txt", "a")
    flowEntropyFile = open("EntropyNetFlow/Detections/FlowEntropy.txt", "a")
    flowEntropyRateFile = open("EntropyNetFlow/Detections/FlowEntropyRate.txt", "a")#RUN THIS AGAIN
    flowFile = open("ThresholdNetFlow/Detections/NumberOfFlows.txt", "a")
    icmpRatioFile = open("ThresholdNetFlow/Detections/ICMPRatio.txt", "a")#RUN THIS AGAIN

    srcEntropyFile.write("Time, Change, Value, Mean of the last 10 minutes")
    srcEntropyRateFile.write("Time, Change, Value, Mean of the last 10 minutes")
    dstEntropyFile.write("Time, Change, Value, Mean of the last 10 minutes")
    dstEntropyRateFile.write("Time, Change, Value, Mean of the last 10 minutes")
    flowEntropyFile.write("Time, Change, Value, Mean of the last 10 minutes")
    flowEntropyRateFile.write("Time, Change, Value, Mean of the last 10 minutes")
    flowFile.write("Time, Change, Value, Mean of the last 10 minutes")
    icmpRatioFile.write("Time, Change, Value, Mean of the last 10 minutes")

    #TODO:make this an input variable
    startTime = datetime.strptime("2011-01-03 00:00:00", '%Y-%m-%d %H:%M:%S')
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)
    records = []

    ipSrcArray = []
    ipSrcRateArray = []

    ipDstArray = []
    ipDstRateArray = []

    flowArray = []
    flowRateArray = []

    numberOfFlows = []

    icmpRatioArray = []
    i = 0
    
    for rec in infile:
        if rec.stime >= startTime + timedelta(minutes = 1):
            PiSIP, ns = ipSourceDistribution(records)
            entropySip = generalizedEntropy(10,PiSIP)
            ipSrcArray.append(entropySip)
            ipSrcRateArray.append(entropySip/ns)

            PiDIP, nd = ipDestinationDistribution(records)
            entropyDip = generalizedEntropy(10,PiDIP)
            ipDstArray.append(entropyDip)
            ipDstRateArray.append(entropyDip/nd)
            
            PiF, nf = flowDistribution(records)
            entropyFlow = generalizedEntropy(10, PiF)
            flowArray.append(entropyFlow)
            flowRateArray.append(entropyFlow/nf)

            numberOfFlows.append(nf)

            icmpRatioArray.append(icmpRatio(records))
            
        
            if i >=10:
                if abs(ipSrcArray[i] - np.nanmean(ipSrcArray[i-10: i-1])) > 1:
                    srcEntropyFile.write("\n" + str(startTime) + "," + str(abs(ipSrcArray[i] - np.nanmean(ipSrcArray[i-10: i-1]))) + "," + str(ipSrcArray[i]) + "," + str(np.nanmean(ipSrcArray[i-10: i-1])))
                
                if abs(ipSrcRateArray[i] - np.nanmean(ipSrcRateArray[i-10: i-1])) > 0.00001:
                    srcEntropyRateFile.write("\n" + str(startTime) + "," + str(abs(ipSrcRateArray[i] - np.nanmean(ipSrcRateArray[i-10: i-1]))) + "," + str(ipSrcRateArray[i]) + "," + str(np.nanmean(ipSrcRateArray[i-10: i-1])))
                
                if abs(ipDstArray[i] - np.nanmean(ipDstArray[i-10: i-1])) > 1:
                    dstEntropyFile.write("\n" + str(startTime) + "," + str(abs(ipDstArray[i] - np.nanmean(ipDstArray[i-10: i-1]))) + "," + str(ipDstArray[i]) + "," + str(np.nanmean(ipDstArray[i-10: i-1])))

                if abs(ipDstRateArray[i] - np.nanmean(ipDstRateArray[i-10: i-1])) >  0.00001:
                    dstEntropyRateFile.write("\n" + str(startTime) + "," + str(abs(ipDstRateArray[i] - np.nanmean(ipDstRateArray[i-10: i-1]))) + "," + str(ipDstRateArray[i]) + "," + str(np.nanmean(ipDstRateArray[i-10: i-1])))

                if abs(flowArray[i] - np.nanmean(flowArray[i-10: i-1])) > 1:
                    flowEntropyFile.write("\n" + str(startTime) + "," + str(abs(flowArray[i] - np.nanmean(flowArray[i-10: i-1]))) + "," + str(flowArray[i]) + "," + str(np.nanmean(flowArray[i-10: i-1])))
                
                if abs(flowRateArray[i] - np.nanmean(flowRateArray[i-10: i-1])) > 0.0001:
                    flowEntropyRateFile.write("\n" + str(startTime) + "," + str(abs(flowRateArray[i] - np.nanmean(flowRateArray[i-10: i-1]))) + "," + str(flowRateArray[i]) + "," + str(np.nanmean(flowRateArray[i-10: i-1])))
                
                if abs(numberOfFlows[i] - np.nanmean(numberOfFlows[i-10: i-1])) > 10000:
                    flowFile.write("\n" + str(startTime) + "," + str(abs(numberOfFlows[i] - np.nanmean(numberOfFlows[i-10: i-1]))) + "," + str(numberOfFlows[i]) + "," + str(np.nanmean(numberOfFlows[i-10: i-1])))

                if abs(icmpRatioArray[i] - np.nanmean(icmpRatioArray[i-10: i-1])) > 0.001:
                    icmpRatioFile.write("\n" + str(startTime) + "," + str(abs(icmpRatioArray[i] - np.nanmean(icmpRatioArray[i-10: i-1]))) + "," + str(icmpRatioArray[i]) + "," + str(np.nanmean(icmpRatioArray[i-10: i-1])))

            records = []
            startTime = startTime + timedelta(minutes = 1)
            i+= 1
        records.append(rec)
        
    srcEntropyFile.close()
    srcEntropyRateFile.close()
    dstEntropyFile.close()
    dstEntropyRateFile.close()
    flowEntropyFile.close()
    flowEntropyRateFile.close()
    flowFile.close()
    icmpRatioFile.close()

    infile.close()
    



#detection("/home/linneafg/silk-data/RawDataFromFilter/two-hours-2011-01-01_10-11.rw") #Sorted on time
detection("/home/linneafg/silk-data/RawDataFromFilter/one-week-2011-01-03_03-10-sorted.rw")