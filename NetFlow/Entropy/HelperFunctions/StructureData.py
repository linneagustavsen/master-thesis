'''
    Structure data to separate the timestamps from the values
    Specific for InfluxDB data
    Input:  df:             pandas dataframe, dataframe containing values with corresponding timestamps
    Output: timeStamps:     list
            measurements:   list
'''
def structureDataTelemetry(df):
    timeStamps = df["_time"].to_numpy()
    measurements = df.values[:,1:]
    return timeStamps, measurements

'''
    Structure data to separate the timestamps from the values
    Specific for SiLK NetFlow data
    Input:  df:             pandas dataframe, dataframe containing values with corresponding timestamps
    Output: sTime:          list
            eTime:          list
            measurements:   list
'''
def structureData(df):
    sTime = df["sTime"].to_numpy()
    eTime = df["eTime"].to_numpy()
    measurements = df.values[:,2:]
    return sTime, eTime, measurements

'''
    Structure data to separate the timestamps from the values
    Specific for SiLK NetFlow data to use for entropy calculations
    Input:  df:             pandas dataframe, dataframe containing values with corresponding timestamps
    Output: timeStamps:     list
            measurements:   list
'''
def structureDataEntropy(df):
    timeStamps = df["time"].to_numpy()
    measurements = df.values[:,1:]
    return timeStamps, measurements

