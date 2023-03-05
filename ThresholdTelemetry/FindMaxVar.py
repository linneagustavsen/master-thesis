def findMaxVar(jsonObject):
    maxVar = 0
    for weekday in range(7):
        for hour in range(24):
            for minute in range(60):
                varianceNow = jsonObject["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]["variance"] 
                if varianceNow > maxVar:
                    maxVar = varianceNow
    return maxVar