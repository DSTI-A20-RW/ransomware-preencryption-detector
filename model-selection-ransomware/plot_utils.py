import os
import pandas as pd
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import plotly.graph_objs as go



def save_figures_to_html(file_path, figs):
    
    #Create folders if they don't exist
    folder_path = os.path.dirname(file_path)
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    
    #Save the figure to an HTML file
    with open(file_path, 'a') as f:
        for fig in figs:
            f.write(fig.to_html(full_html=False, include_plotlyjs='cdn'))

            
            
def plot_evaluation_boxplots(results, names, title, y_axis):
    
    scores_dict = {name : scores for name, scores in zip(names, results)}
    df = pd.DataFrame(scores_dict)
    
    vmin, vmax = df.min().min(), df.max().max()

    norm = matplotlib.colors.Normalize(vmin=vmin, vmax=vmax)
    cmap = matplotlib.cm.get_cmap('GnBu')

    traces = []

    for name, scores in zip(names, results):
        
        median = np.median(scores)
        color = 'rgb' + str(cmap(norm(median))[0:3])

        traces.append(go.Box(
            y=scores,
            name=name,
            boxpoints='all',
            jitter=0.5,
            whiskerwidth=0.2,
            fillcolor=color,
            marker=dict(
                size=2,
                color='rgb(0, 0, 0)'
            ),
            line=dict(width=1),
        ))
    
    layout = go.Layout(
        title=title,
        title_x=0.2,
        yaxis_title=y_axis)

    fig = go.Figure(data=traces, layout=layout)
    
    return fig
