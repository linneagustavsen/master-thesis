def check(filename, timestamp):
    with open(filename) as f:
        datafile = f.readlines()
    for line in datafile:
        if timestamp in line:
            return True
    return False
