import matplotlib.pyplot as plt
'''

    Make a plot based on arrays of values and timestamps
    Input:  valueArray: list, list of values to plot
            timeArray:  list of datetime objects, x-axis time data points
            name:       string, name of plot
            path:       string, destination path of plot

'''
def makePlot(valueArray, timeArray, name, path):
    fig, ax = plt.subplots(1, 1, figsize=(20, 5))
    ax.plot(timeArray, valueArray)
    ax.set_xlabel('Time')
    ax.set_ylabel(name)
    fig.tight_layout()
    fig.savefig(path+name+".png")