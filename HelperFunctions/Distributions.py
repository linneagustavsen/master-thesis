'''
    Make a probability distribution based on how many packets there is in each bi-directional flow in a time interval
    Input:  
            records:    list of SiLK flow records
    Output:
            Pi:         list of floats, the probability distribution
            nf:         int, number of different bi-directional flows
'''
def flowDistribution(records):
    #Make dictionaries for how many packets each flow has and the flow itself to correlate the two
    numberOfPacketsPerFlow = {}
    flows = {}
    #A variable to keep track of the total amount of packets in this time interval
    sumOfPackets = 0

    #Loop through each flow record in the time interval
    for rec in records:
        #Define a bi-directional flow as the connection between a source and destination IP address
        flow = (int(rec.sip), int(rec.dip))
        reverse_flow = (int(rec.dip), int(rec.sip))

        #Find the index of the current flow in the dictionary if it exists
        #If not add it to the dictionary 
        if flow in flows:
            index = flows[flow]
        elif reverse_flow in flows:
            index = flows[reverse_flow]
            flow = reverse_flow
        else:
            index = len(flows)
            flows[flow] = index
            numberOfPacketsPerFlow[index] = 0
        #Add the packets of the current flow to the corresponding index in the other dictionary
        numberOfPacketsPerFlow[index] += rec.packets
        sumOfPackets += rec.packets
    
    #Array to keep track of the probability distribution
    Pi = []

    #Loop through each flow in the time interval
    for key, value in numberOfPacketsPerFlow.items():
        #Add the probability of flow having the size that it does to the distribution
        Pi.append(value/sumOfPackets)

    #Return the probabilities and the number of flows in this interval
    return Pi, len(flows)

'''
    Make a probability distribution based on how many packets there is in each uni-directional flow in a time interval
    Input:  
            records:    list of SiLK flow records
    Output:
            Pi:         list of floats, the probability distribution
            nf:         int, number of different flows
'''
def uniDirFlowDistribution(records):
    #Make dictionaries for how many packets each flow has and the flow itself to correlate the two
    numberOfPacketsPerFlow = {}
    flows = {}
    #A variable to keep track of the total amount of packets in this time interval
    sumOfPackets = 0

   #Loop through each flow record in the time interval
    for rec in records:
        #Define a uni-directional flow as the connection between a source and destination IP address
        flow = (int(rec.sip), int(rec.dip))

        #Find the index of the current flow in the dictionary if it exists
        #If not add it to the dictionary 
        if flow in flows:
            index = flows[flow]
        else:
            index = len(flows)
            flows[flow] = index
            numberOfPacketsPerFlow[index] = 0
        #Add the packets of the current flow to the corresponding index in the other dictionary
        numberOfPacketsPerFlow[index] += rec.packets
        sumOfPackets += rec.packets
    
   #Array to keep track of the probability distribution
    Pi = []

    #Loop through each flow in the time interval
    for key, value in numberOfPacketsPerFlow.items():
        #Add the probability of the current destination flow having the size that it does to the distribution
        Pi.append(value/sumOfPackets)
    

    return Pi, len(flows)


'''
    Make a probability distribution based on how many packets there is in each destination flow in a time interval
    Input:  
            records:    list of SiLK flow records
    Output:
            Pi:         list of floats, the probability distribution
            nd:         int, number of different destination flows
'''
def ipDestinationDistribution(records):
    #Make dictionary for how many packets each destination flow has
    numberOfPacketsPerIP ={}
    #A variable to keep track of the total amount of packets in this time interval
    sumOfPackets = 0

    #Loop through each flow record in the time interval
    for rec in records:
        #If the current flow has the same destination IP as a previous flow the number of packets is added to the record of that destination IP
        #If it has not been encountered before it is added to the dictionary
        if int(rec.dip) in numberOfPacketsPerIP:
            numberOfPacketsPerIP[int(rec.dip)] += rec.packets
        else:
            numberOfPacketsPerIP[int(rec.dip)] = rec.packets
        sumOfPackets += rec.packets

    #Array to keep track of the probability distribution
    Pi = []
    
    #Loop through each IP flow in the time interval
    for key, value in numberOfPacketsPerIP.items():
        #Add the probability of the current destination flow having the size that it does to the distribution
        Pi.append(value/sumOfPackets)
    
    #Return the probabilities and the number of destination flows in this interval
    return Pi,len(numberOfPacketsPerIP)

'''
    Make a probability distribution based on how many packets there is in each source flow in a time interval
    Input:  
            records:    list of SiLK flow records
    Output:
            Pi:         list of floats, the probability distribution
            ns:         int, number of different source flows  
'''
def ipSourceDistribution(records):
    #Make dictionary for how many packets each destination flow has
    numberOfPacketsPerIP ={}
    #A variable to keep track of the total amount of packets in this time interval
    sumOfPackets = 0

   #Loop through each flow record in the time interval
    for rec in records:
        #If the current flow has the same source IP as a previous flow the number of packets is added to the record of that source IP
        #If it has not been encountered before it is added to the dictionary
        if rec.sip in numberOfPacketsPerIP:
            numberOfPacketsPerIP[int(rec.sip)] += rec.packets
        else:
            numberOfPacketsPerIP[int(rec.sip)] = rec.packets
        sumOfPackets += rec.packets

    #Array to keep track of the probability distribution
    Pi = []
    
    #Loop through each IP flow in the time interval
    for key, value in numberOfPacketsPerIP.items():
        #Add the probability of the current source flow having the size that it does to the distribution
        Pi.append(value/sumOfPackets)
    
    #Return the probabilities and the number of source flows in this interval
    return Pi,len(numberOfPacketsPerIP)
    
'''
    Make a probability distribution based on how big packets are in a time interval
    Input:  
            bytes:      list telemetry bytes measurements
            packets:    list telemetry bytes measurements
    Output:
            Pi:         list of floats, the probability distribution
            ns:         int, number of different packet sizes
'''
def packetSizeDistribution(bytes, packets):
    #Make dictionary for how many packets each packet size has
    numberOfPacketsOfSizei = {}
    
    #Loop through the measurements that is collected every 2 sec
    for i in range(len(packets)):
        #If there are no packets the size is 0
        if packets[i] == 0:
            size = 0
        else:
            #If there are packets the average size of a packet is calculated for this measurement, cast to an integer, and stored
            size = int(bytes[i]/packets[i])
        #If the size of the packet has been encountered before the number of packets by the number of packets
        if size in numberOfPacketsOfSizei:
            numberOfPacketsOfSizei[size] += packets[i]
        else:
            numberOfPacketsOfSizei[size] = packets[i]
    
    Pi = []

    sumOfNP = sum(numberOfPacketsOfSizei.values())

    #Loop through each packet size in the time interval
    for key, value in numberOfPacketsOfSizei.items():
        #Add the probability of the current packet size having the size that it does to the distribution
        Pi.append(value/sumOfNP)
    
    return Pi, len(numberOfPacketsOfSizei)

def packetSizeDistributionDetection(bytes, packets):
    #Make dictionary for how many packets each packet size has
    numberOfPacketsOfSizei = {}
    
    #Loop through the measurements that is collected every 2 sec
    for i in range(len(packets)):
        #If there are no packets the size is 0
        if packets[i] == 0:
            size = 0
        else:
            #If there are packets the average size of a packet is calculated for this measurement, cast to an integer, and stored
            size = int(bytes[i]/packets[i])
        #If the size of the packet has been encountered before the number of packets by the number of packets
        if size in numberOfPacketsOfSizei:
            numberOfPacketsOfSizei[size] += packets[i]
        else:
            numberOfPacketsOfSizei[size] = packets[i]
    
    Pi = []

    sumOfNP = sum(numberOfPacketsOfSizei.values())

    #Loop through each packet size in the time interval
    for key, value in numberOfPacketsOfSizei.items():
        #Add the probability of the current packet size having the size that it does to the distribution
        Pi.append(value/sumOfNP)
    
    return Pi, len(numberOfPacketsOfSizei), numberOfPacketsOfSizei

'''
    Make a probability distribution based on how big packets are in a time interval
    Input:  
            records:    list of SiLK flow records
    Output:
            Pi:         list of floats, the probability distribution
            ns:         int, number of different packet sizes
'''
def packetSizeDistributionNetFlow(records):
    #Make dictionary for how many packets each packet size has
    numberOfPacketsOfSizei = {}
    
    #Loop through the flow records
    for rec in records:
        #If there are no packets the size is 0
        if rec.packets == 0:
            size = 0
        else:
            #If there are packets the average size of a packet is calculated for this measurement, cast to an integer, and stored
            size = int(rec.bytes/rec.packets)
        #If the size of the packet has been encountered before the number of packets with this size is increased by the number of packets
        if size in numberOfPacketsOfSizei:
            numberOfPacketsOfSizei[size] += rec.packets
        else:
            numberOfPacketsOfSizei[size] = rec.packets
    
    Pi = []

    sumOfNP = sum(numberOfPacketsOfSizei.values())

    #Loop through all of the packet sizes
    for key, value in numberOfPacketsOfSizei.items():
        #Add the probability of the current packet size being the size that it does to the distribution
        Pi.append(value/sumOfNP)
    
    return Pi, len(numberOfPacketsOfSizei)

'''
    Make a probability distribution based on how big packets are in a time interval
    Input:  
            records:    list of SiLK flow records
    Output:
            Pi:         list of floats, the probability distribution
            ns:         int, number of different packet sizes
'''
def packetSizeDistributionDetectionNetFlow(records):
    #Make dictionary for how many packets each packet size has
    numberOfPacketsOfSizei = {}
    
    #Loop through the flow records
    for rec in records:
        #If there are no packets the size is 0
        if rec.packets == 0:
            size = 0
        else:
            #If there are packets the average size of a packet is calculated for this measurement, cast to an integer, and stored
            size = int(rec.bytes/rec.packets)
        #If the size of the packet has been encountered before the number of packets with this size is increased by the number of packets
        if size in numberOfPacketsOfSizei:
            numberOfPacketsOfSizei[size] += rec.packets
        else:
            numberOfPacketsOfSizei[size] = rec.packets
    
    Pi = []

    sumOfNP = sum(numberOfPacketsOfSizei.values())

    #Loop through all of the packet sizes
    for key, value in numberOfPacketsOfSizei.items():
        #Add the probability of the current packet size being the size that it does to the distribution
        Pi.append(value/sumOfNP)
    
    return Pi, len(numberOfPacketsOfSizei), numberOfPacketsOfSizei

'''
    Calculates the ratio of ICMP packets and number of ICMP packets in a time interval
    Input:  
            records:        list of SiLK flow records
    Output:
            ICMP ratio:     float, the ratio
            icmpPackets:    int, number of ICMP packets in the time interval
'''
def icmpDistribution(records):
    icmpPackets = 0
    packets = 0

    #Loop through the flow records in a time interval
    for rec in records:
        #Check if the flow is of the ICMP protocol
        #If it is we count up the packets in the flow
        if rec.protocol == 1 or rec.protocol == 58:
            icmpPackets += rec.packets
        else:
            packets += rec.packets
    if packets == 0:
        ratio = 0
    else:
        ratio = icmpPackets/packets
    #Return the ratio of ICMP packets to the number of packets of other protocols and the number of ICMP packets
    return ratio, icmpPackets

'''
    Returns the number of packets in an input array of records
    Input:  
            records:    list of SiLK flow records
    Output:
            np:         int, number of packets in the time interval
'''
def numberOfPackets(records):
    np = 0

    for rec in records:
        np+= rec.packets

    return np

'''
    Returns the number of bytes in an input array of records
    Input:  
            records:    list of SiLK flow records
    Output:
            nb:         int, number of bytes in the time interval
'''
def numberOfBytes(records):
    nb = 0

    for rec in records:
        nb+= rec.bytes

    return nb