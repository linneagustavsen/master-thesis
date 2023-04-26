from time import sleep

def simulateRealTime(timeNow, stime, attackDate):
    sleep (timeNow.replace(year=2011, month=1, day=2) - stime).total_seconds()