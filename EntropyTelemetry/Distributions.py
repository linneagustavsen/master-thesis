def numberOfPacketsDistribution(dfEgressPackets):
    egressPackets = dfEgressPackets["_value"].to_numpy()
    
    Pi = []
    sumOfNP = sum(egressPackets)
    for value in egressPackets:
        Pi.append(value/sumOfNP)
    return Pi
    

def packetSizeDistribution(dfEgressBytes, dfEgressPackets):
    egressBytes = dfEgressBytes["_value"].to_numpy()
    egressPackets = dfEgressPackets["_value"].to_numpy()

    numberOfPacketsOfSizei = {}
    packetSize = []
    for i in range(len(egressBytes)):
        if egressPackets[i] == 0:
            packetSize.append(0)
        else:
            size = int(egressBytes[i]/egressPackets[i])
            packetSize.append(size)
            if size in numberOfPacketsOfSizei:
                numberOfPacketsOfSizei[size] += 1
            else:
                numberOfPacketsOfSizei[size] = 1
    
    Pi = []
    sumOfNP = sum(numberOfPacketsOfSizei.values())
    for value in packetSize:
        Pi.append(numberOfPacketsOfSizei.get(value,0)/sumOfNP)
    
    return Pi, len(numberOfPacketsOfSizei)
