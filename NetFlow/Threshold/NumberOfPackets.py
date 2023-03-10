'''
    Returns the number of packets in an input array of records
'''

def numberOfPackets(records):
    np = 0

    for rec in records:
        np+= rec.packets

    return np