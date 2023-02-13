import matplotlib.pyplot as plt

def makePlot(valueArray, timeArray, name):
    fig, ax = plt.subplots(1, 1, figsize=(20, 5))
    ax.plot(timeArray, valueArray)
    ax.set_xlabel('Time')
    ax.set_ylabel(name)
    fig.tight_layout()
    fig.savefig("EntropyNetFlow/Plots/"+name+".png")