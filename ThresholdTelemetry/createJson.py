import json

json_object ={
    "weekday": {
    }
}

hours =[]
minutes=[]
for hour in range(24):
    hours.append(str(hour))
for minute in range(60):
        minutes.append(str(minute))


json_object["weekday"] = dict.fromkeys("0123456", dict(hour = None))
for weekday in range(6):
    json_object["weekday"][str(weekday)]["hour"] = dict.fromkeys(hours,dict(minute = None) )
    for hour in range(24):
        json_object["weekday"][str(weekday)]["hour"][str(hour)]["minute"] = dict.fromkeys(minutes, dict(mean = None, variance = None))

json_file_mean_var = open("MeanVarSchema.json", "w")
json.dump(json_object,json_file_mean_var)
json_file_mean_var.close()
