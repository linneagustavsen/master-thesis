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
    # Plot a histogram for each IP address
    for ip_freqs in listOfDicts:
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
        ax.text(2000, 300, text)
        y_fit = func(xData, *fittedParameters)
        ax.plot(xData, y_fit, color='red')
        #ax.set_yscale('log')
        ax.set_title("Destination IP distribution, "+ startTime.isoformat(' '))
        ax.set_xlabel('IP addresses')
        ax.set_ylabel("Number of packets")
        ax.set_xlim(0, len(ip_freqs))
        fig.tight_layout()
        fig.savefig(path+startTime.strftime("%d_%m_%y_%H.%M.%S")+".png", dpi=500)
        plt.close(fig)
        
        startTime += timedelta(minutes = 1)

start="2011-01-19 06:56:00"
stop="2011-01-19 08:37:00"

makePlot('NetFlow/Entropy/Calculations/dstDistributionsWeek4Day3.json', 'Plots/Entropy/Curve.NormalScale.DstDistr.', start)