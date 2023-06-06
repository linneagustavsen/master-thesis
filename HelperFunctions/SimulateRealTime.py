import math
from time import sleep
from datetime import timedelta

def simulateRealTime(timeNow, stime, attackDate):
    attackDate = attackDate.split(".")
    attackYear = 2000 + int(attackDate[2])
    attackMonth = int(attackDate[1])
    attackDay = int(attackDate[0])
    
    movedTime = stime - timedelta(minutes=30)
    if movedTime > timeNow.replace(year=attackYear, month=attackMonth, day=attackDay):
        duration = math.ceil((movedTime - timeNow.replace(year=attackYear, month=attackMonth, day=attackDay)).total_seconds())
    else:
        duration = 0
    '''if stime > timeNow.replace(year=attackYear, month=attackMonth, day=attackDay):
        duration = math.ceil((stime - timeNow.replace(year=attackYear, month=attackMonth, day=attackDay)).total_seconds())
    else:
        duration = 0'''
    sleep(duration)
