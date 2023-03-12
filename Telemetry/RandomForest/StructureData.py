def structureData(df):
    timeStamps = df["_time"].to_numpy()
    measurements = df.values[:,1:]
    return timeStamps, measurements