import matplotlib.pyplot as plt
import json
from datetime import datetime, timedelta
import matplotlib.dates as mdates
import pandas as pd

'''
    Make a plot based on arrays of values and timestamps
'''
def makePlot(y_field, y_fieldName):
    x_values = []
    y_values = [[] for _ in range(8)]  # Initialize empty lists for 7 weeks
    date = "2023-05-11"
    
    for week in range(1,9):
        with open("Telemetry/Threshold/Calculations/WeeklyPattern/week"+ str(week)+ str(y_field)+ ".csv", 'r') as f:
            data = pd.read_csv(f)
            times = pd.to_datetime(data["Time"])
            values = pd.to_numeric(data["Value"])
        i = 0
        for timestamp in times:
            if week == 1:
                day = timestamp.strftime('%w')
                if day == '0':
                    date = "2023-05-14"
                if day == '1':
                    date = "2023-05-15"
                if day == '2':
                    date = "2023-05-16"
                if day == '3':
                    date = "2023-05-17"
                if day == '4':
                    date = "2023-05-11"
                if day == '5':
                    date = "2023-05-12"
                if day == '6':
                    date = "2023-05-13"
                hour = timestamp.hour
                minute = timestamp.minute
                date_string = f'{date}-{hour}-{minute}'
                date_obj = datetime.strptime(date_string, '%Y-%m-%d-%H-%M')
                x_values.append(date_obj)

            y_values[week-1].append(values[i])
            i += 1
 
                    
    #print(x_values)    
    fig, axs = plt.subplots(1, 1, figsize=(20, 5))

    for i, y_week in enumerate(y_values):
        axs.plot(x_values, y_week, label=f"Week {i+1}")
    axs.xaxis.set(
        major_locator=mdates.DayLocator(),
        major_formatter=mdates.DateFormatter("\n\n%A\n"),
        minor_locator=mdates.HourLocator((0, 12)),
        minor_formatter=mdates.DateFormatter("%H"),
    )
    axs.set_title(y_fieldName + " for 8 weeks")
    axs.set_xlabel('Time')
    axs.set_ylabel(y_fieldName)
    axs.tick_params(axis='both', which='major', labelsize=12)
    axs.legend()
    fig.tight_layout()
    fig.savefig("Plots/Threshold/Telemetry/WeeklyPattern/"+ y_field+".png", dpi=500)
    plt.close()


y_fields = ["egress_octets"]
y_field_names = ["Egress octets per second"]
counter1 = 0
makePlot(y_fields[counter1], y_field_names[counter1])
