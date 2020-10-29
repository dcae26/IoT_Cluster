#!/usr/bin/env python
# coding: utf-8

# In[1]:


import numpy as np
import pandas as pd


# In[2]:


# Read data
iot_data_dir = "../result/"

print("Reading data...",end='')
raw_encoded = pd.read_csv(iot_data_dir + "instance.csv")
raw_mds = pd.read_csv(iot_data_dir + "min_distribution.csv")
print("Success.")


# In[3]:


def autocorrelation(x, lags):
    # calculate autocorrelation in lags, return lags number of numbers
    n = len(x)
    res = [np.correlate(x[i:]-x[i:].mean(),x[:n-i]-x[:n-i].mean())[0]        /(x[i:].std()*x[:n-i].std()*(n-i))         for i in range(1,lags+1)]
    return res


# In[4]:


def period_detection(seqs, threshold=0.85, lags=60):
    self_co = np.zeros((seqs.shape[0],))
    np.seterr(invalid='ignore')
    for i in range(0, seqs.shape[0]):
        print("\rPeriod Processing "+str(i+1)+"/"+str(seqs.shape[0]),end='')
        self_co[i] = np.nanmax(autocorrelation(seqs[i], 60))
    self_co = np.nan_to_num(self_co)
    print("\nDone.")
    return self_co


# In[5]:


def burst_threshold(y, lag, threshold, influence):
    # Z-score thresholding
    signals = np.zeros(len(y))
    filteredY = np.array(y)
    avgFilter = [0]*len(y)
    stdFilter = [0]*len(y)
    avgFilter[lag - 1] = np.mean(y[0:lag])
    stdFilter[lag - 1] = np.std(y[0:lag])
    for i in range(lag, len(y) - 1):
        if abs(y[i] - avgFilter[i-1]) > threshold * stdFilter [i-1]:
            if y[i] > avgFilter[i-1]:
                signals[i] = 1
            else:
                signals[i] = -1

            filteredY[i] = influence * y[i] + (1 - influence) * filteredY[i-1]
            avgFilter[i] = np.mean(filteredY[(i-lag):i])
            stdFilter[i] = np.std(filteredY[(i-lag):i])
        else:
            signals[i] = 0
            filteredY[i] = y[i]
            avgFilter[i] = np.mean(filteredY[(i-lag):i])
            stdFilter[i] = np.std(filteredY[(i-lag):i])
    return np.asarray(signals).sum()


# In[6]:


def burst_detection(seqs, win_size=5, threshold=10, influence=0.5):
    res = np.zeros((seqs.shape[0],))
    for i in range(0, seqs.shape[0]):
        print("\rBurst Processing "+str(i+1)+"/"+str(seqs.shape[0]),end='')
        res[i] = burst_threshold(seqs[i], win_size, threshold, influence)
    print("\nDone.")
    return res


# In[7]:


# Create Burst Feature
burst = burst_detection(raw_mds.iloc[:,2:].values)
print("Burst feature vector: ", burst)
print("Burst shape: ", burst.shape)


# In[8]:


# Create Period Feature
period = period_detection(raw_mds.iloc[:,2:].values)
print("Period feature vector: ", period)
print("Period shape: ", period.shape)


# In[9]:


# Save Features to instance.csv
burst = burst.reshape((burst.shape[0],1))
period = period.reshape((period.shape[0],1))

raw_encoded["burst"] = burst
raw_encoded["period"] = period

print("Saving to "+iot_data_dir+"instance.csv ",end='')
raw_encoded.to_csv(iot_data_dir + "instance.csv", index=False)
print("Done.")

