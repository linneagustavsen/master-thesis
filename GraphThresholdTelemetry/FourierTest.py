from scipy.fft import rfft,rfftfreq,irfft
from scipy import signal
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

df = pd.read_pickle("GraphThresholdTelemetry/DataFrames/Week2.pkl")
traffic = df['_value'].to_numpy()
timeAxis = df['_time'].to_numpy()

n    = len(traffic)
yf   = rfft(traffic)
psd = yf * np.conj(yf) / n
ind = np.argpartition(psd, -50)[-50:]

mask_array = np.zeros(len(yf), dtype=int)
mask_array[ind] = 1
yf_clean = yf*mask_array

new_f_clean = irfft(yf_clean)
print(new_f_clean)
plt.plot(timeAxis[:-1],new_f_clean)
plt.show()
