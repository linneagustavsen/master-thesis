'''

rwfilter --start-date=2011/01/01:10 --end-date=2011/01/01:11 --all-destination=/home/linneafg/silk-data/RawDataFromFilter/one-hour-2010-12-01_10-11.rw --data-rootdir=/home/linneafg/silk-data/oslo-gw

'''

# Import the PySiLK bindings
from silk import *
from IPSourceDistribution import *
from IPDestinationDistribution import *
from FlowDistribution import *
from GeneralizedEntropy import *
from ICMPRatio import *
from datetime import datetime,timedelta
from MakePlot import *
import time


# Main function
def detection(silkFile):

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

    timeArray = []
    counter = 0
    st = time.time()
    for rec in infile:
        if rec.stime >= startTime + timedelta(minutes = 1):
            '''PiSIP, ns = ipSourceDistribution(records)
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

            numberOfFlows.append(nf)'''

            icmpRatioArray.append(icmpRatio(records))
            
            timeArray.append(rec.stime)
        
            print("Runde:",counter)
            print("Record stime:", rec.stime)
            print("--- %s seconds ---" % (time.time() - st))
            records = []
            startTime = startTime + timedelta(minutes = 1)
            st = time.time()
            counter+= 1
        records.append(rec)
        

    infile.close()
    '''
    makePlot(ipSrcArray, timeArray, "Entropy of Source IP 1 week")
    makePlot(ipSrcRateArray, timeArray, "Entropy rate of Source IP 1 week")
    
    makePlot(ipDstArray, timeArray, "Entropy of Destination IP 1 week")
    makePlot(ipDstRateArray, timeArray, "Entropy rate of Destination IP 1 week")
    
    makePlot(flowArray, timeArray, "Entropy of Flows 1 week")
    makePlot(flowRateArray, timeArray, "Entropy rate of Flows 1 week")
    
    makePlot(numberOfFlows, timeArray, "Number of flows 1 week")'''

    makePlot(icmpRatioArray, timeArray, "ICMP ratio 1 week")



#detection("/home/linneafg/silk-data/RawDataFromFilter/two-hours-2011-01-01_10-11.rw") #Sorted on time
detection("/home/linneafg/silk-data/RawDataFromFilter/one-week-2011-01-03_03-10-sorted.rw")