import json

json_file_mean_var = open("ThresholdTelemetry/RawValues/MeanVarValues.json", "r")
json_file_mean_var_denoised = open("ThresholdTelemetry/RawValues/MeanVarValuesDeNoised.json", "r")
json_object_mean_var = json.load(json_file_mean_var)
json_object_mean_var_denoised = json.load(json_file_mean_var_denoised)
json_file_mean_var_denoised.close()
json_file_mean_var.close()

for weekday in range(7):
    for hour in range(24):
        for minute in range(60):
            normal = json_object_mean_var["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]
            denoised = json_object_mean_var_denoised["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)]
            if abs(normal["mean"]- denoised["mean"]) > 0.0001:
                print("Normal mean:",normal["mean"], "denoised mean:", denoised["mean"], "difference:",normal["mean"]- denoised["mean"])
            '''if abs(normal["variance"]- denoised["variance"]) > 10:
                print("Normal variance:",normal["variance"], "denoised variance:", denoised["variance"], "difference:",normal["variance"]- denoised["variance"])'''