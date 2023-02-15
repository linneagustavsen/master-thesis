'''
    #Get icmp packets with destination AS 224 in the oslo-gw:
	rwfilter --start-date=2011/01/03:00 --end-date=2011/01/10:00 --proto=6,56 --flags-all=S/SA --pass-destination=/home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in.rw --data-rootdir=/home/linneafg/silk-data/oslo-gw
	
    #Sorts them by start time
	rwsort --fields=stime --output-path=/home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in-sorted.rw  /home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in.rw 

'''

# Import the PySiLK bindings
from silk import *
from MakePlot import *
from SYNPacketDistribution import *
from GeneralizedEntropy import *
from datetime import datetime, timedelta

def synDetection(silkFile):

    #startTime = datetime.strptime("2010-12-26 06:00:00", '%Y-%m-%d %H:%M:%S')
    startTime = datetime.strptime("2011-01-03 00:00:00", '%Y-%m-%d %H:%M:%S')
    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)
    records = []

    # Open a silk flow file for reading
    infile = silkfile_open(silkFile, READ)
    synPacketsPerFlow = []

    entropyOfSynPacketsPerDst = []
    entropyOfSynPacketsPerSrc = []
    entropyOfSynPacketsPerFlow = []

    timeArray = []
    for rec in infile:
        '''
        From https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8423699: During DDoS, entropy distribution concerning destination IP tends to be less random.
        
        '''
      
        if rec.stime >= startTime + timedelta(minutes = 1):

            PiDIP, nd = synPacketsFromDstDistr(records)
            entropyDip = generalizedEntropy(10,PiDIP)
            entropyOfSynPacketsPerDst.append(entropyDip)

            PiSIP, ns = synPacketsFromSrcDistr(records)
           
            entropySip = generalizedEntropy(10,PiSIP)
            entropyOfSynPacketsPerSrc.append(entropySip)

            PiF, nf = synPacketsPerFlowDistr(records)
            entropyFlow = generalizedEntropy(10,PiF)
            entropyOfSynPacketsPerFlow.append(entropyFlow)

            

    infile.close()

    '''
    makePlot(entropyOfSynPacketsPerDst, timeArray, "Entropy of SYN packets per destination address entire period")
    makePlot(entropyOfSynPacketsPerSrc, timeArray, "Entropy of SYN packets per source address entire period")
    makePlot(entropyOfSynPacketsPerFlow, timeArray, "Entropy of SYN packets per flow (IPsrc, IPdst) entire period")
  '''
synDetection("/home/linneafg/silk-data/RawDataFromFilter/tcp-syn-in-sorted.rw")
#synDetection("/home/linneafg/silk-data/RawDataFromFilter/tcpSyn-in-sorted-time.rw")