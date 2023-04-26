import math
from time import sleep

def simulateRealTime(timeNow, stime, attackDate):
    attackDate = attackDate.split(".")
    attackYear = 2000 + int(attackDate[2])
    attackMonth = int(attackDate[1])
    attackDay = int(attackDate[0])
    if stime > timeNow:
        duration = math.ceil((stime- timeNow.replace(year=attackYear, month=attackMonth, day=attackDay)).total_seconds())
    else:
        duration = 0
    sleep(duration)