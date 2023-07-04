from datetime import datetime, timezone
import pandas as pd


def inAttackInterval(stime, etime, attackDate):
    stime = pd.Timestamp(stime)
    etime = pd.Timestamp(etime)
    if attackDate == "08.03.23":
        strings = [["Mar 08 14:29:55", "Mar 08 14:34:56"], ["Mar 08 14:49:56", "Mar 08 15:02:57"],
        ["Mar 08 15:09:56", "Mar 08 15:17:02"], ["Mar 08 15:37:00", "Mar 08 15:52:02"]]
        attacks = ["SYN Flood", "SlowLoris", "Ping Flood", "R.U.D.Y"]
    elif attackDate == "17.03.23":
        strings = [["Mar 17 11:00:01", "Mar 17 11:07:02"], ["Mar 17 11:37:02", "Mar 17 11:50:04"],
        ["Mar 17 11:57:02", "Mar 17 12:04:12"], ["Mar 17 12:44:10", "Mar 17 13:00:17"]]
        attacks = ["SYN Flood", "SlowLoris", "Ping Flood", "R.U.D.Y"]
    elif attackDate == "24.03.23":
        strings = [["Mar 24 14:00:01", "Mar 24 14:03:57"], ["Mar 24 14:13:29", "Mar 24 14:29:08"],
        ["Mar 24 14:46:30", "Mar 24 14:55:00"], ["Mar 24 14:59:50", "Mar 24 15:15:06"], 
        ["Mar 24 15:26:51", "Mar 24 15:39:22"], ["Mar 24 15:40:21", "Mar 24 15:47:50"], 
        ["Mar 24 16:07:29", "Mar 24 16:19:00"], ["Mar 24 16:22:29", "Mar 24 16:29:13"],
        ["Mar 24 16:29:53", "Mar 24 16:49:50"], ["Mar 24 16:53:22", "Mar 24 17:09:39"],
        ["Mar 24 17:25:15", "Mar 24 17:47:00"]]
        attacks = ["UDP Flood", "SlowLoris", "Ping Flood", "Slow Read", "Blacknurse", "SYN Flood", "R.U.D.Y",
            "Xmas", "UDP Flood and SlowLoris", "Ping Flood and R.U.D.Y", "All types"]
    attackIntervals = []  
    for string in strings:
        start = datetime.strptime(string[0], '%b %d %H:%M:%S').replace(year=2023).replace(tzinfo=timezone.utc)
        stop = datetime.strptime(string[1], '%b %d %H:%M:%S').replace(year=2023).replace(tzinfo=timezone.utc)


        intervalNow = pd.Interval(pd.Timestamp(start), pd.Timestamp(stop), closed="both")
        attackIntervals.append(intervalNow)
    
    isAttack = False
    attackType = ""
    counter = 0
    for interval in attackIntervals:
        if stime in interval or etime in interval:
            isAttack = True
            attackType = attacks[counter]
        counter +=1
    return isAttack, attackType