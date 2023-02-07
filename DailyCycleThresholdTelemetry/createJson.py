import json
'''
json_object ={
    "hour": {
    }
}
json_object_raw ={
    "hour": {
    }
}

hours =[]
minutes=[]
for hour in range(24):
    hours.append(str(hour))
for minute in range(60):
        minutes.append(str(minute))


json_object["hour"] = dict.fromkeys(hours,dict(minute = None))
json_object_raw["hour"] = dict.fromkeys(hours,dict(minute = None))
for hour in range(24):
    json_object["hour"][str(hour)]["minute"] = dict.fromkeys(minutes, dict(mean = None, variance = None))
    json_object_raw["hour"][str(hour)]["minute"] = dict.fromkeys(minutes, [])

json_file_mean_var = open("DailyCycleThresholdTelemetry/Schemas/MeanVarSchema.json", "w")
json_file_raw = open("DailyCycleThresholdTelemetry/Schemas/RawValuesSchema.json", "w")
json.dump(json_object,json_file_mean_var)
json_file_mean_var.close()
json.dump(json_object_raw,json_file_raw)
json_file_raw.close()'''

