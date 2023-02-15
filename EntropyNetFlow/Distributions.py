def flowDistribution(infile):
    numberOfPacketsPerFlow = {}
    flows = {}
    sumOfPackets = 0
    for rec in infile:
        flow = (rec.sip, rec.dip)
        reverse_flow = (rec.dip, rec.sip)
        if flow in flows:
            index = flows[flow]
        elif reverse_flow in flows:
            index = flows[reverse_flow]
            flow = reverse_flow
        else:
            index = len(flows)
            flows[flow] = index
            numberOfPacketsPerFlow[index] = 0
        numberOfPacketsPerFlow[index] += rec.packets
        sumOfPackets += rec.packets
    
    Pi = []
    for rec in infile:
        flow = (rec.sip, rec.dip)
        reverse_flow = (rec.dip, rec.sip)
        if flow in flows:
            index = flows[flow]
        elif reverse_flow in flows:
            index = flows[reverse_flow]
        Pi.append(numberOfPacketsPerFlow[index]/sumOfPackets)

    return Pi, len(flows)

def ipDestinationDistribution(infile):
    numberOfPacketsPerIP ={}
    sumOfPackets = 0

    # Loop over the records in the file
    for rec in infile:
        if rec.dip in numberOfPacketsPerIP:
            numberOfPacketsPerIP[rec.dip] += rec.packets
        else:
            numberOfPacketsPerIP[rec.dip] = rec.packets
        sumOfPackets += rec.packets

    Pi = []
    
    for rec in infile:
        Pi.append(numberOfPacketsPerIP[rec.dip]/sumOfPackets)
    
    return Pi,sumOfPackets

def ipSourceDistribution(infile):

    numberOfPacketsPerIP ={}
    sumOfPackets = 0

    # Loop over the records in the file
    for rec in infile:
        if rec.sip in numberOfPacketsPerIP:
            numberOfPacketsPerIP[rec.sip] += rec.packets
        else:
            numberOfPacketsPerIP[rec.sip] = rec.packets
        sumOfPackets += rec.packets

    Pi = []
    
    for rec in infile:
        Pi.append(numberOfPacketsPerIP[rec.sip]/sumOfPackets)
    
    return Pi,sumOfPackets