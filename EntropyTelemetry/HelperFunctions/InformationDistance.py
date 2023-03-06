import math

'''

    Input: list of probabilities of two distributions, the alpha, and the length of the distribution lists
    Output: Information distance

'''

def informationDistance(alpha, Pi, Qi, n):
    sum1 = 0
    sum2 = 0
    for i in range(n):
        sum1 += (Pi[i]**alpha)*(Qi[i]**(1-alpha))
        sum2 += (Qi[i]**alpha)*(Pi[i]**(1-alpha))
    
    return 1/(1-alpha)*math.log(sum1*sum2, 2)