import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import glob
from pprint import pprint as print
from mpl_toolkits.axes_grid1 import make_axes_locatable
import collections
import operator

vals = {}
names = []
maxvals= {}
for i, file in enumerate(glob.glob('*.csv')):
    print((i, file))
    names.append(file.replace('.csv',''))
    df = pd.read_csv(file, sep=';')
    linesum = sum(1 for line in open(file))
    cval=0
    for key, group in df.groupby('API Name'):
        if key not in vals:
            vals[key] = {}
        vals[key][i] = len(group)
        if len(group)>cval:
            cval=len(group)
            maxvals[file]=key,cval,linesum, round((cval/linesum)*100,2)
            #maxvals[file]=cval
#print(maxvals)
#foo = collections.OrderedDict(sorted(vals.items(), key=lambda t: t[1]['10']))
#print(foo)
for i in range(len(names)):
    top_calls = []
    for callname, doccounts in vals.items():
        top_calls.append((callname, doccounts.get(i, 0)))
    top_calls.sort(key=lambda tup: -tup[1])
    print("{0} , {1}".format(names[i], top_calls[:3]))

heatmap = np.zeros(shape=(i + 1, len(vals)))
colLabels = {}
for j, (k, v) in enumerate(vals.items()):
    for i, s in v.items():
        heatmap[i, j] = s
    colLabels[j] = k
maxheat=np.copy(heatmap)
#print(heatmap.shape)
#print(heatmap.sum(axis=1))
#print(heatmap.sum(axis=1).shape)
#print (heatmap)

heatmap /= heatmap.sum(axis=1,keepdims=True)
maxheat -=maxheat.max(axis=1,keepdims=True)
maxheat[maxheat< 0] = np.NaN
#maxheat*=heatmap
maxheat[maxheat== 0] = 1
heatmap[heatmap == 0] = np.NaN
heatmap = np.log10(heatmap)
for i,im in enumerate([heatmap,maxheat]):
    fig = plt.figure(figsize=(20, 20))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])
    img=ax.imshow(im, interpolation='nearest', cmap='plasma')
    #plt.colorbar()
    xlabels = [k for _, k in sorted(colLabels.items(), key=lambda tup: tup[0])]
    ylabels = names
    ax.set_xticks(np.arange(0, len(im[0])))
    ax.set_yticks(np.arange(0,len(names)))
    ax.set_xticklabels(xlabels)
    ax.set_yticklabels(ylabels)
    plt.xticks(rotation=90)

    ax =plt.gca()
    divider = make_axes_locatable(ax)
    cax = divider.append_axes("right",size="2%", pad=0.05)
    plt.colorbar(img,cax=cax)
    ax.set_title('ZW Calls')
    cax.set_yticklabels(['Few calls','','','','Many calls'])
    plt.savefig('output{}.png'.format(i))
