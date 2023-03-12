import pandas as pd
from HelperFunctions.MakePlot import *

df_historic= pd.read_csv('NetFlow/HistoricEntropy/Calculations/Metrics.attack.08.03.csv')
df_interval= pd.read_csv('NetFlow/Entropy/Calculations/Metrics.attack.08.03.csv')

'''makePlot(df_historic['srcEntropy'], df_historic['Time'], "historicSrcEntropy", "NetFlow/HistoricEntropy/Plots/")
makePlot(df_interval['srcEntropy'], df_interval['Time'], "intervalSrcEntropy", "NetFlow/HistoricEntropy/Plots/")
makePlot(df_historic['dstEntropy'], df_historic['Time'], "historicDstEntropy", "NetFlow/HistoricEntropy/Plots/")
makePlot(df_interval['dstEntropy'], df_interval['Time'], "intervalDstEntropy", "NetFlow/HistoricEntropy/Plots/")
makePlot(df_historic['flowEntropy'], df_historic['Time'], "historicFlowEntropy", "NetFlow/HistoricEntropy/Plots/")
makePlot(df_interval['flowEntropy'], df_interval['Time'], "intervalFlowEntropy", "NetFlow/HistoricEntropy/Plots/")'''

def makeMultiplePlots(valueArray1, valueArray2, timeArray, name, path):
    fig, ax = plt.subplots(1, 1, figsize=(20, 5))
    ax.plot(timeArray, valueArray1, label='historic')
    ax.plot(timeArray, valueArray2, label='interval')
    ax.set_xlabel('Time')
    ax.set_ylabel(name)
    ax.legend()
    fig.tight_layout()
    fig.savefig(path+name+".png")

makeMultiplePlots(df_historic['srcEntropy'], df_interval['srcEntropy'], df_historic['Time'], "bothSrcEntropy", "NetFlow/HistoricEntropy/Plots/")
makeMultiplePlots(df_historic['dstEntropy'], df_interval['dstEntropy'], df_historic['Time'], "bothDstEntropy", "NetFlow/HistoricEntropy/Plots/")
makeMultiplePlots(df_historic['flowEntropy'], df_interval['flowEntropy'], df_historic['Time'], "bothFlowEntropy", "NetFlow/HistoricEntropy/Plots/")
