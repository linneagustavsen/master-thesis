from datetime import timedelta
from silk import *
from .AttackTimestamps import attackTimestamps

amazonuw3_mp = IPv4Addr('44.232.96.55')
amazonuw3_mp6 = IPv6Addr('2600:1f14:5b9:3b00:7c8f:fb81:3dd3:f8c4')

amazonff2_mp6 = IPv6Addr('2a05:d014:c07:5d00:d58f:b117:785:2455')
amazonff2_mp = IPv4Addr('3.64.103.227')

amazonie2_mp6 = IPv6Addr('2a05:d018:1d6d:b800:b792:c146:2c31:3a56')
amazonie2_mp = IPv4Addr('63.33.90.46')

amazonsth2_mp6 = IPv6Addr('2a05:d016:cb:8600:bd0e:6306:bd6d:633e')
amazonsth2_mp = IPv4Addr('16.170.114.107')

ytelse_brg = IPv4Addr('158.39.1.94')
ytelse_brg6 = IPv6Addr('2001:700:0:4302::2')

ytelse_osl = IPv4Addr('158.39.1.126')
ytelse_osl6 = IPv6Addr('2001:700:0:412d::2')

ytelse_tos = IPv4Addr('158.39.1.98')
ytelse_tos6 = IPv6Addr('2001:700:0:8035::2')

ytelse_trd = IPv4Addr('158.39.1.90')
ytelse_trd6 = IPv6Addr('2001:700:0:4527::2')

trondheim_mp = IPv4Addr('128.39.65.26')
trondheim_mp6 = IPv6Addr('2001:700:0:452a::26')
'''ip_addresses = [amazonuw3_mp, amazonff2_mp, amazonie2_mp, amazonsth2_mp, ytelse_brg, ytelse_osl, ytelse_tos, ytelse_trd]
ipv6_addresses = [amazonuw3_mp6, amazonff2_mp6, amazonie2_mp6, amazonsth2_mp6, ytelse_brg6, ytelse_osl6, ytelse_tos6, ytelse_trd6]'''
victim = trondheim_mp
victim6 = trondheim_mp6
ip_addresses = [ytelse_brg, ytelse_osl, ytelse_tos, ytelse_trd]
ipv6_addresses = [ytelse_brg6, ytelse_osl6, ytelse_tos6, ytelse_trd6]

'''
    Checks whether a flow is an attack flow or not
    Input:
            sip:    SiLK IPv4Addr object, the source IP of the flow record
            dip:    SiLK IPv4Addr object, the destination IP of the flow record
    Output:
                    boolean, whether the flow is an attack flow or not
'''
def isAttackFlow(sip, dip, start, end):
    if ((sip in ip_addresses and dip == victim) or (sip == victim and dip in ip_addresses) or (sip in ipv6_addresses and dip == victim6) or 
        (sip == victim6 and dip in ipv6_addresses) or (sip in ipv6_addresses and dip == victim) or (sip == victim and dip in ipv6_addresses) or 
        (sip in ip_addresses and dip == victim6) or (sip == victim6 and dip in ip_addresses)) and isAttack(start, end):
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
        time = start.replace(tzinfo=None) + timedelta(seconds = i)
        if time.replace(microsecond=0) in attackTimestamps:
            exists = True
    return exists