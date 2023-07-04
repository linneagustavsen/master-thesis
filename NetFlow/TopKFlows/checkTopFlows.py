import json
from datetime import datetime,timedelta
json_file = open("NetFlow/TopKFlows/Calculations/topKflows.json", "r")
distributions = json.load(json_file)
json_file.close()
start="2011-01-19 06:56:00"
start = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
lastDistribution = distributions[0]
change = False
maxPercentage = 0
percentage = [] 
'''for distribution in distributions:
    for i in range(len(lastDistribution)):
        if distribution[i][2] > maxPercentage:
            maxPercentage = distribution[i][2]
            percentage = distribution[i]
            percentage.append(str(start))
        if lastDistribution[i][0] != distribution[i][0] and distribution[i][2]/lastDistribution[i][2] > 1.5:
            print(i+1, distribution[i], lastDistribution[i], distribution[i][2]/lastDistribution[i][2])
            change = True
    if change:
        print(str(start))
        print("-----------------------------------------------------------------------------------------------------")
        change = False
    lastDistribution = distribution
    start += timedelta(minutes = 1)
print(percentage)'''


for distribution in distributions:
    exists = False
    for i in range(len(distribution)):
        for j in range(len(lastDistribution)):
            if distribution[i][0] == lastDistribution[j][0]:
                exists = True
    print(exists)
    if not exists:
        print(i+1, distribution[i][0], lastDistribution)
        change = True
    if change:
        print(str(start))
        print("-----------------------------------------------------------------------------------------------------")
        change = False
    lastDistribution = distribution
    start += timedelta(minutes = 1)


import matplotlib.pyplot as plt
import json
from datetime import datetime, timedelta
from scipy.optimize import curve_fit
import numpy as np
import math


# "x" is data, a,b,c are parameters
def func(x, a, b, c, d):
   #np.multiply(a,np.exp(np.divide(1, np.multiply(-b,x)))) # example function
   return a/(b*x**c+d) # example function

def makePlot(jsonFile, path, start):
    startTime = datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    with open(jsonFile, 'r') as f:
        listOfDicts = json.load(f)
    print(len(listOfDicts))
    startPlot = datetime.strptime("2011-01-19 08:03:00", '%Y-%m-%d %H:%M:%S')
    stopPlot = datetime.strptime("2011-01-19 08:10:00", '%Y-%m-%d %H:%M:%S')
    # Plot a histogram for each IP address
    for ip_freqs in listOfDicts:
        print(startTime, startPlot, stopPlot)
        if startTime >= stopPlot:
            break
        if startTime < startPlot:
            startTime += timedelta(minutes = 1)
            continue
    
        print(len(ip_freqs))
        xData = np.asarray(list(range(1,len(ip_freqs)+1)))
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.bar(xData, ip_freqs.values())
        vals = np.fromiter(ip_freqs.values(),int)
        print(vals)
        print(xData)
        fittedParameters, pcov = curve_fit(func, xData, vals)
        print(fittedParameters)
        a1 = fittedParameters[0]
        b1= fittedParameters[1]
        c1= fittedParameters[2]
        d1= fittedParameters[3]
        text = str(str(a1)+ "/" + str(b1)+"x^"+str(c1)+ "+"+str(d1))
        ax.text(5, 1000, text)
        y_fit = func(xData, *fittedParameters)
        ax.plot(xData, y_fit, color='red')
        plt.xticks(np.arange(20), ip_freqs.keys(), rotation=50)
        #ax.set_yscale('log')
        ax.set_title("Destination IP distribution, "+ startTime.isoformat(' '))
        ax.set_xlabel('IP addresses')
        ax.set_ylabel("Number of packets")
        ax.set_xlim(0, len(ip_freqs))
        fig.tight_layout()
        fig.savefig(path+startTime.strftime("%d_%m_%y_%H.%M.%S")+".pdf", dpi=300)
        plt.close(fig)
        
        startTime += timedelta(minutes = 1)

start="2011-01-19 06:56:00"
stop="2011-01-19 08:37:00"

makePlot('NetFlow/TopKFlows/Calculations/topKflowsDict.json', 'Plots/TopKFlows/Curve.NormalScale.DstDistr.', start)