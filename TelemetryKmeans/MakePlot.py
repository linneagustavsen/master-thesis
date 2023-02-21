import matplotlib.pyplot as plt
'''

    Make a plot based on arrays of values and timestamps

'''
def makePlot(valueArray, timeArray, name):
    fig, ax = plt.subplots(1, 1, figsize=(20, 5))
    ax.plot(timeArray, valueArray)
    ax.set_xlabel('Time')
    ax.set_ylabel(name)
    fig.tight_layout()
    fig.savefig("TelemetryKmeans/Plots/"+name+".png")