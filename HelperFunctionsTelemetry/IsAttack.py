from datetime import timedelta
from silk import *
from .AttackTimestamps import attackTimestamps
googleeu_mp = IPv4Addr('34.105.154.156')
amazonuw2_mp = IPv4Addr('18.236.63.8')
amazonff_mp = IPv4Addr('3.69.241.159')
amazonie_mp = IPv4Addr('34.254.179.150')
amazonsth_mp = IPv4Addr('13.48.73.156')
azure_mp = IPv4Addr('13.82.53.167')
azurene_mp = IPv4Addr('13.79.144.22')
googlefi_mp = IPv4Addr('35.228.220.215')
ytelse_brg = IPv4Addr('158.39.1.94')
ytelse_osl = IPv4Addr('158.39.1.126')
ytelse_tos = IPv4Addr('158.39.1.98')
ytelse_trd = IPv4Addr('158.39.1.90')
trondheim_mp = IPv4Addr('128.39.65.26')
ip_addresses_cloud = [googleeu_mp, amazonuw2_mp, amazonff_mp, amazonie_mp, amazonsth_mp, azure_mp, azurene_mp, googlefi_mp, ytelse_brg, ytelse_osl, ytelse_tos, ytelse_trd, trondheim_mp]
ip_addresses = [ytelse_brg, ytelse_osl, ytelse_tos, ytelse_trd]
victim = trondheim_mp

'''
    Checks whether a flow is an attack flow or not
    Input:
            sip:    SiLK IPv4Addr object, the source IP of the flow record
            dip:    SiLK IPv4Addr object, the destination IP of the flow record
    Output:
                    boolean, whether the flow is an attack flow or not
'''
def isAttackFlow(sip, dip, start, end):
    if ((sip in ip_addresses and dip == victim) or (sip == victim and dip in ip_addresses)) and isAttack(start, end):
        return True
    else:
        return False

'''
    Checks whether a period is an attack period or not
    Input:
            start:  datetime object, the start time of a potential attack period
            end:    datetime object, the end time of a potential attack period
    Output:
                        boolean, whether the period is an attack period or not
'''
def isAttack(start, end):
    exists = False
    for i in range(int((end-start).total_seconds())+1):
        time = start + timedelta(seconds = i)
        if time.replace(microsecond=0) in attackTimestamps:
            exists = True
    return exists