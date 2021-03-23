import os
import time
import json
import pandas as pd
import numpy as np
import glob2
from itertools import repeat
from multiprocessing import Pool, Process, current_process, cpu_count


def get_file_list(folder_path, extensions =['zip']):
    ''' Returns the list of files with all given extensions inside the specified folder in the current working directory, '''
    file_list = []
    for extension in extensions:
        file_list.extend(glob2.glob(os.path.join(folder_path, '*.' + extension)))
    return file_list


def json_to_dict(json_file):
  with open(json_file, 'rb') as f:
    json_report = json.load(f)
  return json_report


def get_index(json_report, index_value):
  try:
      return json_report['file_information'][index_value]
  except Exception as e:
      raise Exception('get_index ERROR', e)


def get_label(json_report, category):
  try:
      return json_report['file_class'][category + '_label']
  except Exception as e:
      raise Exception('get_label ERROR', e)

def set_metadata(selection, json_report, index_value = 'md5', category = 'class'):
  selection[index_value] = get_index(json_report, index_value)
  selection['label'] = get_label(json_report, category)


def get_encoded_apistats(json_file, one_hot=False):
  try:
    print('Processing :', json_file)
    json_report =  json_to_dict(json_file)
    apistats = json_report['api_calls']['apistats']
    set_metadata(apistats, json_report)
    encoded_apistats = pd.json_normalize(apistats, max_level=0).set_index('md5')
    if one_hot == True:
      label = encoded_apistats['label']
      features = encoded_apistats.drop('label', axis=1)
      features[features!=0] = 1
      encoded_apistats = features.join(label)
    print('Processed :', json_file)
    return encoded_apistats
  except Exception as e:
    print('KEY ERROR', e)


def main():
    
    json_files_path = os.path.join(os.getcwd(), 'extracted')

    json_files_list = get_file_list(json_files_path, extensions=['json'])

    start = time.time()

    one_hot = True

    pool = Pool()
    dfs = pool.starmap(get_encoded_apistats, zip(json_files_list, repeat(one_hot)))
    pool.close()
    pool.join() 

    print('Processing took : {} s'.format(time.time()-start))

    new_dfs = []
    cpu_cores = cpu_count()
    for i in range(cpu_cores):
        dfs_subset = [dfs[j] for j in range(len(dfs)) if j % cpu_cores == i]
        if len(dfs_subset) > 0:
            new_dfs.append(dfs_subset)

    pool = Pool()
    final_dfs = pool.map(pd.concat, new_dfs)
    pool.close()
    pool.join()

    try:
        df = pd.concat(final_dfs, axis=0, ignore_index=False).replace(np.nan, 0).astype(np.int32)
        print(df.head())
        print(df.shape)
        df.to_csv(os.getcwd() + os.sep + 'onehot_encoded_dataset.csv')

    except Exception as e:
        print('Concatenating dataframes failed', e)

    print('Concatenation and saving file took : {} s'.format(time.time() - start))

    

if __name__ == '__main__':
    main()