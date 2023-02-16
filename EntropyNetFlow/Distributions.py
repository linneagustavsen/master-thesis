'''

    Make a probability distribution based on how many packets there is in each bi-directional flow in a time interval

'''
def flowDistribution(infile):
    #Make dictionaries for how many packets each flow has and the flow itself to correlate the two
    numberOfPacketsPerFlow = {}
    flows = {}
    #A variable to keep track of the total amount of packets in this time interval
    sumOfPackets = 0

    #Loop through each flow record in the time interval
    for rec in infile:
        #Define a bi-directional flow as the connection between a source and destination IP address
        flow = (rec.sip, rec.dip)
        reverse_flow = (rec.dip, rec.sip)

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

    #Loop through each flow record in the time interval
    for rec in infile:
        flow = (rec.sip, rec.dip)
        reverse_flow = (rec.dip, rec.sip)
        if flow in flows:
            index = flows[flow]
        elif reverse_flow in flows:
            index = flows[reverse_flow]
        #Add the probability of the current flow having the size that it does to the distribution
        Pi.append(numberOfPacketsPerFlow[index]/sumOfPackets)

    #Return the probabilities and the number of flows in this interval
    return Pi, len(flows)


'''

    Make a probability distribution based on how many packets there is in each destination flow in a time interval

'''
def ipDestinationDistribution(infile):
    #Make dictionaries for how many packets each destination flow has
    numberOfPacketsPerIP ={}
    #A variable to keep track of the total amount of packets in this time interval
    sumOfPackets = 0

    #Loop through each flow record in the time interval
    for rec in infile:
        #If the current flow has the same destination IP as a previous flow the number of packets is added to the record of that destination IP
        #If it has not been encountered before it is added to the dictionary
        if rec.dip in numberOfPacketsPerIP:
            numberOfPacketsPerIP[rec.dip] += rec.packets
        else:
            numberOfPacketsPerIP[rec.dip] = rec.packets
        sumOfPackets += rec.packets

    #Array to keep track of the probability distribution
    Pi = []
    
    #Loop through each flow record in the time interval
    for rec in infile:
        #Add the probability of the current destination flow having the size that it does to the distribution
        Pi.append(numberOfPacketsPerIP[rec.dip]/sumOfPackets)
    
    #Return the probabilities and the number of destination flows in this interval
    return Pi,len(numberOfPacketsPerIP)

'''

    Make a probability distribution based on how many packets there is in each source flow in a time interval

'''
def ipSourceDistribution(infile):
    #Make dictionaries for how many packets each destination flow has
    numberOfPacketsPerIP ={}
    #A variable to keep track of the total amount of packets in this time interval
    sumOfPackets = 0

   #Loop through each flow record in the time interval
    for rec in infile:
        #If the current flow has the same source IP as a previous flow the number of packets is added to the record of that source IP
        #If it has not been encountered before it is added to the dictionary
        if rec.sip in numberOfPacketsPerIP:
            numberOfPacketsPerIP[rec.sip] += rec.packets
        else:
            numberOfPacketsPerIP[rec.sip] = rec.packets
        sumOfPackets += rec.packets

    #Array to keep track of the probability distribution
    Pi = []
    
    #Loop through each flow record in the time interval
    for rec in infile:
        #Add the probability of the current source flow having the size that it does to the distribution
        Pi.append(numberOfPacketsPerIP[rec.sip]/sumOfPackets)
    
    #Return the probabilities and the number of source flows in this interval
    return Pi,len(numberOfPacketsPerIP)