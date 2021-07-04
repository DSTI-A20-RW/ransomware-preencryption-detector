import os
import time
import logging
from functools import wraps
import pickle
import re

import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)
logger.setLevel("INFO")
handler = logging.StreamHandler()
logger.addHandler(handler)


## DEBUGGING

def timed(func):
    """This decorator prints the execution time for the decorated function."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        logger.info("EXECUTION TIME : {} ran in {}s".format(func.__name__, round(end - start, 2)))
        return result

    return wrapper



## DATA MANIPULATION


def get_data(folder_path=None, file_name=None, file_path=None, index = 'md5', compression=None):
    '''
    Load pandas object from file path.
    
    Parameters:
    -----------
    file_path or ( folder_path, file_name ) : str 
       Filepath/URL of pandas object. Specify one or the other. 
    index : str, default 'md5'
       Column to use as the row labels of the dataframe.
    compression : {‘infer’, ‘gzip’, ‘bz2’, ‘zip’, ‘xz’, None}
       Decompression type. Set to None for no decompression.
           
    Returns:
    --------
    A pandas dataframe.
    '''
    
    #define file path
    if file_path is None:
        file_path = os.path.join(folder_path, file_name)
        
    #extract extension
    path, extension = os.path.splitext(file_path)
    if compression is not None:
        path, extension = os.path.splitext(path)
    
    #load data
    if extension == '.csv':
        df = pd.read_csv(file_path, index_col=index, compression=compression)
    if extension in ['.pickle', '.pkl']:
        df = pd.read_pickle(file_path, compression=compression)#.set_index(index)
        
    #print shape 
    print('loaded data shape :'.ljust(20), df.shape)
    
    return df


def pickle_results(results, file, path='nested-cv-results'):
    file_path = os.path.join(path, file)
    pickle.dump(results, open( file_path, "wb" ), protocol=pickle.HIGHEST_PROTOCOL)
    
    
def unpickle_results(file, path='nested-cv-results'):
    file_path = os.path.join(path, file)
    return pickle.load(open( file_path, "rb" ))