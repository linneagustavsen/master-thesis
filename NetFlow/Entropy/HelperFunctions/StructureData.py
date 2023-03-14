def structureData(df):
    sTime = df["sTime"].to_numpy()
    eTime = df["eTime"].to_numpy()
    measurements = df.values[:,2:]
    return sTime, eTime, measurements

def structureDataEntropy(df):
    timeStamps = df["time"].to_numpy()
    measurements = df.values[:,1:]
    return timeStamps, measurements

