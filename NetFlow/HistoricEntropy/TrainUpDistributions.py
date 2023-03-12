from TrainDistributions import *
from silk import *
import pickle

def trainDistrbutions(silkFile):
    infile = silkfile_open(silkFile, READ)
    numberOfPacketsPerFlow, flows,sumOfPackets = flowDistribution(infile)
    with open('NetFlow/HistoricEntropy/Distributions/numberOfPacketsPerBiDirFlow.pkl', 'wb') as fp:
        pickle.dump(numberOfPacketsPerFlow, fp)
    print("Finished")
    with open('NetFlow/HistoricEntropy/Distributions/BiDirFlows.pkl', 'wb') as fp:
        pickle.dump(flows, fp)
    print("Finished")
    with open('NetFlow/HistoricEntropy/Distributions/SumOfPacketsBiDirFlow.pkl', 'wb') as fp:
        pickle.dump(sumOfPackets, fp)
    print("Finished")
    
    numberOfPacketsPerFlow, flows, sumOfPackets = uniDirFlowDistribution(infile)
    with open('NetFlow/HistoricEntropy/Distributions/numberOfPacketsPerUniDirFlow.pkl', 'wb') as fp:
        pickle.dump(numberOfPacketsPerFlow, fp)
    print("Finished")
    with open('NetFlow/HistoricEntropy/Distributions/UniDirFlows.pkl', 'wb') as fp:
        pickle.dump(flows, fp)
    print("Finished")
    with open('NetFlow/HistoricEntropy/Distributions/SumOfPacketsUniDirFlow.pkl', 'wb') as fp:
        pickle.dump(sumOfPackets, fp)
    print("Finished")
    
    numberOfPacketsPerIP,sumOfPackets = ipDestinationDistribution(infile)
    with open('NetFlow/HistoricEntropy/Distributions/numberOfPacketsPerDstIP.pkl', 'wb') as fp:
        pickle.dump(numberOfPacketsPerIP, fp)
    print("Finished")
    with open('NetFlow/HistoricEntropy/Distributions/SumOfPacketsDstIP.pkl', 'wb') as fp:
        pickle.dump(sumOfPackets, fp)
    print("Finished")

    numberOfPacketsPerIP,sumOfPackets = ipSourceDistribution(infile)
    with open('NetFlow/HistoricEntropy/Distributions/numberOfPacketsPerSrcIP.pkl', 'wb') as fp:
        pickle.dump(numberOfPacketsPerIP, fp)
    print("Finished")
    with open('NetFlow/HistoricEntropy/Distributions/SumOfPacketsSrcIP.pkl', 'wb') as fp:
        pickle.dump(sumOfPackets, fp)
    print("Finished")

trainDistrbutions("/home/linneafg/silk-data/RawDataFromFilter/one-week-2011-01-03_03-10-sorted.rw")