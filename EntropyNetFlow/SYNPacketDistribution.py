def synPacketsFromDstDistr(records):
    numberOfPacketsPerIP ={}
    sumOfPackets = 0

    # Loop over the records in the file
    for rec in records:
        if rec.dip in numberOfPacketsPerIP:
            numberOfPacketsPerIP[rec.dip] += rec.packets
        else:
            numberOfPacketsPerIP[rec.dip] = rec.packets
        sumOfPackets += rec.packets

    Pi = []
    
    for rec in records:
        Pi.append(numberOfPacketsPerIP[rec.dip]/sumOfPackets)
    
    return Pi,sumOfPackets

def synPacketsFromSrcDistr(records):
    numberOfPacketsPerIP ={}
    sumOfPackets = 0

    # Loop over the records in the file
    for rec in records:
        if rec.sip in numberOfPacketsPerIP:
            numberOfPacketsPerIP[rec.sip] += rec.packets
        else:
            numberOfPacketsPerIP[rec.sip] = rec.packets
        sumOfPackets += rec.packets

    Pi = []
    
    for rec in records:
        Pi.append(numberOfPacketsPerIP[rec.sip]/sumOfPackets)
    
    return Pi,sumOfPackets

def synPacketsPerFlowDistr(records):
    numberOfPacketsPerFlow = {}
    flows = {}
    sumOfPackets = 0
    for rec in records:
        flow = (rec.sip, rec.dip)
        if flow in flows:
            index = flows[flow]
        else:
            index = len(flows)
            flows[flow] = index
            numberOfPacketsPerFlow[index] = 0
        numberOfPacketsPerFlow[index] += rec.packets
        sumOfPackets += rec.packets
    
    Pi = []
    for rec in records:
        flow = (rec.sip, rec.dip)
        if flow in flows:
            index = flows[flow]
        Pi.append(numberOfPacketsPerFlow[index]/sumOfPackets)

    return Pi, len(flows)
