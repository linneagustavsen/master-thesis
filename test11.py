import re
routers = {"trd-gw": "AR1",
                   "ifi2-gw5": "AR2",
                   "bergen-gw3": "AR3",
                   "tromso-gw5": "AR4",
                   "teknobyen-gw1": "VR",  
                   "hoytek-gw2": "CR3"}
# Open the file in read mode
with open('test11.csv', 'r') as file:
   # Read all lines of the file
    lines = file.readlines()
    lineCounter = 0
    # Iterate over each line
    for line in lines:
        # Split the line using a comma not followed by a space
        values = re.split(r',(?!\s)', line.strip())

        # Access the values in each column by their indices
        position = values[0]
        s_time = values[1]
        e_time = values[2]
        gateways = values[3]
        deviation_score = values[4]
        attack_type = values[5]
        real_labels = values[6]

        # Perform your desired changes on each line
        # For example, print the values of each column
        '''print(f"Position: {position}")
        print(f"Start Time: {s_time}")
        print(f"End Time: {e_time}")
        print(f"Gateways: {gateways}")
        print(f"Deviation Score: {deviation_score}")
        print(f"Attack Type: {attack_type}")
        print(f"Real Labels: {real_labels}")
        print()'''
        newValues = [position, s_time, e_time]
        if lineCounter == 0:
            lineCounter+=1
            with open('test12.csv', 'a') as output_file:
                output_file.write(','.join(values))
                output_file.write("\n")
            continue
        newerGateways = list(gateways.replace("[", "").replace("]", "").split("', '"))

        newGateways = ""
        # Perform your modifications on the line here
        for gateway in newerGateways:
            newGateways += routers[gateway.replace("'", "")] + "; "
        newValues.append(newGateways)

        deviationScore = eval(deviation_score)
        deviationScores = ""
        deviationScores += "Mean:" + "%.5f"%deviationScore["mean"] + "; "
        deviationScores += "Standard deviation:" + "%.5f"%deviationScore["standard_deviation"]
        newValues.append(deviationScores)

        attack_type = eval(attack_type)
        attack_type = sorted(attack_type.items(), key=lambda x:x[1], reverse=True)
        attacks = ""
        for attack in attack_type:
            if attack[0] == "":
                attacks += "No type" + ": "+ "%.5f"%attack[1] + "; "
            else:
                attacks += attack[0].replace("'", "") + ": "+ "%.5f"%attack[1] + "; "
        newValues.append(attacks)

        real_labels = eval(real_labels)
        real_labels = sorted(real_labels.items(), key=lambda x:x[1], reverse=True)
        labels = ""
        for label in real_labels:
            labels += label[0].replace("'", "") + ": "+ str(label[1]) + "; "
        newValues.append(labels)

        with open('test12.csv', 'a') as output_file:
            output_file.write(','.join(newValues))
            output_file.write("\n")
        lineCounter+=1