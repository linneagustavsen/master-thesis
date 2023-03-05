'''

    Make a probability distribution based on how big packets are in a time interval

'''
def packetSizeDistribution(egressBytes, egressPackets):
    numberOfPacketsOfSizei = {}
    packetSize = []
    
    #Loop through the measurements that is collected every 2 sec
    for i in range(len(egressPackets)):
        #If there are no packets the size is 0
        if egressPackets[i] == 0:
            size = 0
        else:
            #If there are packets the average size of a packet is calculated for this measurement, cast to an integer, and stored
            size = int(egressBytes[i]/egressPackets[i])
        packetSize.append(size)
        #If the size of the packet has been encountered before the number of packets with this size is increased by one
        if size in numberOfPacketsOfSizei:
            numberOfPacketsOfSizei[size] += 1
        else:
            numberOfPacketsOfSizei[size] = 1
    
    Pi = []

    sumOfNP = sum(numberOfPacketsOfSizei.values())

    #Loop through all of the packet sizes
    for value in packetSize:
        #Add the probability of the current packet size being the size that it does to the distribution
        Pi.append(numberOfPacketsOfSizei[value]/sumOfNP)
    
    return Pi, len(numberOfPacketsOfSizei)
