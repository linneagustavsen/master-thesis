'''
    Function to find the maximum variance in a json object that 
    contains the variance for each minute of each weekday
    Input:  jsonObject: json object, contains the variance for each minute of each weekday
    Output: maxVar:     float, the maximum variance of that week.
'''
def findMaxVar(jsonObject):
    maxVar = 0
    #Loop through every minute of a week
    for weekday in range(7):
        for hour in range(24):
            for minute in range(60):
                #Find the variance of each minute
                varianceNow = jsonObject["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]["variance"] 
                #Compare the variance of this minute with the maximum variance of the week
                if varianceNow > maxVar:
                    maxVar = varianceNow
    return maxVar