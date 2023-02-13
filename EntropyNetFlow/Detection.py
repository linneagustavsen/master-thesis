'''

rwfilter --start-date=2011/01/01:10 --end-date=2011/01/01:11 --all-destination=/home/linneafg/silk-data/RawDataFromFilter/one-hour-2010-12-01_10-11.rw --data-rootdir=/home/linneafg/silk-data/oslo-gw

'''

# Import the PySiLK bindings
from silk import *
from IPSourceDistribution import *
from IPDestinationDistribution import *
from FlowDistribution import *
from GeneralizedEntropy import *
from datetime import datetime,timedelta
from MakePlot import *
import time


# Main function
def detection(silkFile):

    startTime = datetime.strptime("2011-01-01 10:00:00", '%Y-%m-%d %H:%M:%S')
    stopTime = datetime.strptime("2011-01-01 11:00:00", '%Y-%m-%d %H:%M:%S')
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

    timeArray = []
    counter = 0
    st = time.time()
    for rec in infile:
        if rec.stime >= startTime + timedelta(minutes = 1):
            PiSIP, ns = ipSourceDistribution(records)
            ipSrcArray.append(generalizedEntropy(10,PiSIP))
            ipSrcRateArray.append(generalizedEntropy(10,PiSIP)/ns)

            PiDIP, nd = ipDestinationDistribution(records)
            ipDstArray.append(generalizedEntropy(10,PiDIP))
            ipDstRateArray.append(generalizedEntropy(10,PiDIP)/nd)
            
            PiF, nf = flowDistribution(records)
            flowArray.append(generalizedEntropy(10, PiF))
            flowRateArray.append(generalizedEntropy(10,PiF)/nf)

            numberOfFlows.append(nf)
            
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

    makePlot(ipSrcArray, timeArray, "Entropy of Source IP 1m")
    makePlot(ipSrcRateArray, timeArray, "Entropy rate of Source IP 1m")
    
    makePlot(ipDstArray, timeArray, "Entropy of Destination IP 1m")
    makePlot(ipDstRateArray, timeArray, "Entropy rate of Destination IP 1m")
    
    makePlot(flowArray, timeArray, "Entropy of Flows 1m")
    makePlot(flowRateArray, timeArray, "Entropy rate of Flows 1m")
    
    makePlot(numberOfFlows, timeArray, "Number of flows 1m")



detection("/home/linneafg/silk-data/RawDataFromFilter/two-hours-2011-01-01_10-11.rw") #Sorted on time