'''
    Check if timestamp is in file
    Input:  filename:   string, name of file to search
            timestamp:  string, timestamp to find in file
    Output:             boolean, if the timestamp is in the file or not
'''
def checkLabel(filename, timestamp):
    with open(filename) as f:
        datafile = f.readlines()
    for line in datafile:
        if timestamp in line:
            return True
    return False
