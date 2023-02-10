import numpy as np

def packetSizeDistribution(dfEgressBytes, dfEgressPackets):
    egressBytes = dfEgressBytes["_value"].to_numpy()
    bytesTime = dfEgressBytes["_time"].to_numpy()

    egressPackets = dfEgressPackets["_value"].to_numpy()
    packetsTime = dfEgressPackets["_time"].to_numpy()

    numberOfPacketsOfSizei = np.zeros(1514)
    packetSize = []
    for i in range(len(egressBytes)):
        if egressPackets[i] == 0:
            packetSize.append(0)
        else:
            packetSize.append(egressBytes[i]/egressPackets[i])
    
    for value in packetSize:
        numberOfPacketsOfSizei[int(value)] += 1
        
    
    Pi = []
    sumOfNP = sum(numberOfPacketsOfSizei)
    for value in packetSize:
        Pi.append(numberOfPacketsOfSizei[int(value)]/sumOfNP)
    
    return Pi, np.count_nonzero(numberOfPacketsOfSizei)
    