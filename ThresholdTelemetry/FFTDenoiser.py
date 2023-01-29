import numpy as np
import json

def fft_denoiser(x, n_components, to_real=True):
    """Fast fourier transform denoiser.
    
    Denoises data using the fast fourier transform.
    
    Parameters
    ----------
    x : numpy.array
        The data to denoise.
    n_components : int
        The value above which the coefficients will be kept.
    to_real : bool, optional, default: True
        Whether to remove the complex part (True) or not (False)
        
    Returns
    -------
    clean_data : numpy.array
        The denoised data.
        
    References
    ----------
    .. [1] Steve Brunton - Denoising Data with FFT[Python]
       https://www.youtube.com/watch?v=s2K1JfNR7Sc&ab_channel=SteveBrunton
    
    """
    n = len(x)
    
    # compute the fft
    fft = np.fft.fft(x, n)
    
    # compute power spectrum density
    # squared magnitud of each fft coefficient
    PSD = fft * np.conj(fft) / n
    
    # keep high frequencies
    _mask = PSD > n_components
    fft = _mask * fft
    
    # inverse fourier transform
    clean_data = np.fft.ifft(fft)
    
    if to_real:
        clean_data = clean_data.real
    
    return clean_data

'''
json_file = open("/home/linneafg/Code/master-thesis/RawValues.json", "r")
json_object_raw = json.load(json_file)
json_file.close()

for minute in range(10): 
    test["weekday"][str(0)]["hour"][str(0)]["minute"][str(minute)] = fft_denoiser(json_object_raw["weekday"][str(0)]["hour"][str(0)]["minute"][str(minute)], 50)
    print("DENOISED:", test["weekday"][str(0)]["hour"][str(0)]["minute"][str(minute)])
    print("NORMAL:", json_object_raw["weekday"][str(0)]["hour"][str(0)]["minute"][str(minute)])
    
    for i in range(len(test["weekday"][str(0)]["hour"][str(0)]["minute"][str(minute)])):
        if test["weekday"][str(0)]["hour"][str(0)]["minute"][str(minute)][i] != json_object_raw["weekday"][str(0)]["hour"][str(0)]["minute"][str(minute)][i]:
            print("Difference in i:", abs(test["weekday"][str(0)]["hour"][str(0)]["minute"][str(minute)][i] - json_object_raw["weekday"][str(0)]["hour"][str(0)]["minute"][str(minute)][i]), "\n")

#The difference is microscopical'''