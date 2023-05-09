'''
    Structure data to separate the timestamps from the values
    Specific for InfluxDB data
    Input:  
            df:             pandas dataframe, dataframe containing values with corresponding timestamps
    Output: 
            timeStamps:     list
            measurements:   list
'''
def structureDataTelemetry(df):
    timeStamps = df["_time"].to_numpy()
    measurements = df.values[:,1:]
    return timeStamps, measurements

def structureDataTelemetryLabels(df):
    timeStamps = df["_time"].to_numpy()
    measurements = df.values[:,1:-1]
    labels = df.values[:,-1]
    return timeStamps, measurements, labels

'''
    Structure data to separate the timestamps from the values
    Specific for SiLK NetFlow data
    Input:  
            df:             pandas dataframe, dataframe containing values with corresponding timestamps
    Output: 
            sTime:          list, contains the start time stamps
            eTime:          list, contains the end time stamps
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
    Input:  
            df:             pandas dataframe, dataframe containing values with corresponding timestamps
    Output: 
            timeStamps:     list
            measurements:   list
'''
def structureDataEntropy(df):
    timeStamps = df["time"].to_numpy()
    measurements = df.values[:,1:-1]
    labels = df.values[:,-1]
    return timeStamps, measurements, labels


def structureDataNumpyArrays(npArray):
    sTime = npArray[:,0]
    eTime = npArray[:,1]
    measurements = npArray[:,2:-1]
    labels = npArray[:,-1]
    return sTime, eTime, measurements, labels

def structureDataEntropyNumpyArrays(npArray):
    timeStamps = npArray[:, 0]
    measurements = npArray[:,1:-1]
    labels = npArray[:,-1]
    return timeStamps, measurements, labels