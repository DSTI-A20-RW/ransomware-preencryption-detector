import os
import time
import json
import orjson
import pandas as pd
import numpy as np
import glob2
import pickle
from itertools import repeat
from multiprocessing import Pool, Process, current_process, cpu_count


def get_file_list(folder_path, extensions =['zip']):
    ''' Returns the list of files with all given extensions inside the specified folder in the current working directory, '''
    file_list = []
    for extension in extensions:
        file_list.extend(glob2.glob(os.path.join(folder_path, '*.' + extension)))
    return file_list


def json_to_dict(json_file):
  '''This function returns dictionary format of the given json file'''
  with open(json_file, 'r') as f:
    json_report = orjson.loads(f.read())
  return json_report


def get_index(json_report, index_value):
  '''This function returns index value from "file information" of json report'''
  try:
      return json_report['file_information'][index_value]
  except Exception as e:
      raise Exception('get_index ERROR', e)


def get_label(json_report, category):
  '''This function is used to retrieve the sample label, e.g. malware, ransomware and goodware'''
  try:
      return json_report['file_class'][category + '_label']
  except Exception as e:
      raise Exception('get_label ERROR', e)


def set_metadata(selection, json_report, index_value):
  '''This function is used to set metadata, e.g. label is used for malware-goodware
    case and sublabel is used for ransomware-malware case respectively'''
  selection[index_value] = get_index(json_report, index_value)
  selection['label'] = get_label(json_report, 'class')
  selection['sublabel'] = get_label(json_report, 'subclass')


def get_encoded_apistats(json_file, one_hot = False, index_value = 'md5'):
  '''This function returns one hot encoded API stats data from json report'''
  try:
    print('Processing :', json_file)
    json_report =  json_to_dict(json_file)
    apistats = json_report['api_calls']['apistats']
    set_metadata(apistats, json_report, index_value)
    encoded_apistats = pd.json_normalize(apistats, max_level=0).set_index(index_value)
    if one_hot == True:
      labels = encoded_apistats[['label', 'sublabel']]
      features = encoded_apistats.drop(['label', 'sublabel'], axis=1)
      features[features!=0] = 1
      encoded_apistats = features.join(labels)
    print('Processed :', json_file)
    return encoded_apistats
  except Exception as e:
    print('KEY ERROR', e)


def remove_dll(dlls, substring = ['virusshare', 'cucko'], unique=True):
    '''This function returns DLL feature list, leaving only unique values'''
    occurences = []
    if unique:
        dlls = list(set([ os.path.splitext(dll.lower().replace(os.path.sep, '/'))[0] for dll in dlls ]))
    for dll in dlls:
        for target in substring:
            if target in dll :
                if dll not in occurences:
                    occurences.append(dll)
    for dll in occurences:
        dlls.remove(dll)
    return dlls

def get_encoded_dll_loaded(json_file, index_value = 'md5'):
  '''this function returns one hot encoded DLL data'''
  try:
    print('Processing :', json_file)
    json_report =  json_to_dict(json_file)
    dll_loaded = json_report['dll_loaded']['loaded_dll']
    pruned_dll_loaded = remove_dll(dll_loaded, substring = ['virusshare', 'cucko'], unique=True)
    dll_loaded_todict = { dll : 1 for dll in pruned_dll_loaded }
    set_metadata(dll_loaded_todict, json_report, index_value)
    encoded_dll_loaded = pd.json_normalize(dll_loaded_todict, max_level=0).set_index(index_value)
    print('Processed :', json_file)
    return encoded_dll_loaded
  except Exception as e:
    print('dll_loaded KEY ERROR', e)



def get_file_operations_counts(json_file, index_value = 'md5'):
  '''This function retrieves file operations count features.'''
  try:
    print('Processing :', json_file)
    json_report =  json_to_dict(json_file)
    file_operations_counts = json_report['file_operations']['files_counts']
    set_metadata(file_operations_counts, json_report, index_value)
    encoded_file_operations = pd.json_normalize(file_operations_counts, max_level=0).set_index(index_value)
    print('Processed :', json_file)
    return encoded_file_operations
  except Exception as e:
    print('file_operations_counts KEY ERROR', e)



def get_regkeys_counts(json_file, index_value = 'md5'):
  '''This function retrieves registry keys operations count features.'''
  try:
    print('Processing :', json_file)
    json_report =  json_to_dict(json_file)
    regkeys_counts = json_report['regkeys']['regkey_counts']
    set_metadata(regkeys_counts, json_report, index_value)
    encoded_regkeys_counts = pd.json_normalize(regkeys_counts, max_level=0).set_index(index_value)
    print('Processed :', json_file)
    return encoded_regkeys_counts
  except Exception as e:
    print('regkeys_counts KEY ERROR', e)


def get_encoded_pe_imports(json_file, dll_name = None, index_value = 'md5'):
  '''This function retrieves one hot encoded PE Imports features'''
  try:
    print('Processing :', json_file)
    json_report =  json_to_dict(json_file)
    pe_imports = json_report['pe_analysis']['pe_imports']
    if dll_name is not None:
        pe_imports_todict = { import_ : 1 for import_ in pe_imports[dll_name] }
    else:
        pe_imports_todict = { dll_name_ : 1 for dll_name_ in pe_imports.keys() }
    set_metadata(pe_imports_todict, json_report, index_value)
    encoded_pe_imports = pd.json_normalize(pe_imports_todict, max_level=0).set_index(index_value)
    print('Processed :', json_file)
    return encoded_pe_imports
  except Exception as e:
    print('pe_imports KEY ERROR', e)



def get_regkeys(json_file, category, index_value = 'md5'):
  '''This function retrieves nested registry keys features.'''
  try:
    print('Processing :', json_file)
    json_report =  json_to_dict(json_file)
    regkeys = json_report['regkeys']['regkey_values'][category]
    regkeys_todict = {k:1 for k in regkeys}
    set_metadata(regkeys_todict, json_report, index_value)
    encoded_regkeys = pd.json_normalize(regkeys_todict, max_level=0).set_index(index_value)
    print('Processed :', json_file)
    return encoded_regkeys
  except Exception as e:
    print(f'regkeys {category} KEY ERROR', e)



def get_key(nested_key, level=1, sep=os.path.sep):
  '''This function deals with separating values in registry keys features, 
    as they ususally contain path information and other details'''
  keys = [key.lower() for key in nested_key.split(sep)]
  try:
    return keys[:level]
  except:
    if level > 1:
      return get_key(nested_key, level=level-1)
    else:
      pass

def get_all_keys(regkeys, level=1, unique=True, sep='/'):
  '''This function returns list of unique nested registry key values up to a certain level'''
  results = []
  for nested_key in regkeys:
    results.extend(get_key(nested_key, level=level, sep=sep))
  if unique:
    results = list(set(results))
  return results

def remove_keys(keys, substring=None, numeric=True):
    '''This function removes unwanted symbols in nested registry keys data'''
    occurences = []
    for key in keys:
        if numeric:
            if key.replace('.', '').replace('-', '').isnumeric():
                occurences.append(key)
        for target in substring:
            if target in key:
                occurences.append(key)

    for key in occurences:
        keys.remove(key)
    return keys

def get_nested_regkeys(json_file, category, level = 15, index_value = 'md5'):
  '''This function retrieves all nested registry keys from json, cleaned and encoded.'''
  try:
    print('Processing :', json_file)
    json_report =  json_to_dict(json_file)
    regkeys = json_report['regkeys']['regkey_values'][category]
    nested_regkeys = get_all_keys(regkeys, level=level, sep='\\')
    pruned_nested_regkeys = remove_keys(nested_regkeys, substring=['virusshare', 'cucko', 'default'], numeric=True)
    nested_regkeys_todict = {k:1 for k in pruned_nested_regkeys}
    set_metadata(nested_regkeys_todict, json_report, index_value)
    encoded_nested_regkeys = pd.json_normalize(nested_regkeys_todict, max_level=0).set_index(index_value)
    print('Processed :', json_file)
    return encoded_nested_regkeys
  except Exception as e:
    print(f'Nested Regkeys {category} KEY ERROR', e)


def get_nested_fileops(json_file, category, level = 15, index_value = 'md5'):
  '''This function retrieve nested file operations from json, cleaned and encoded'''
  try:
    print('Processing :', json_file)
    json_report =  json_to_dict(json_file)
    fileops = json_report['file_operations']['files_values'][category]
    nested_files = get_all_keys(fileops, level=level, sep='\\')
    pruned_nested_files = remove_keys(nested_files, substring=['virusshare', 'cucko', 'default'], numeric=True)
    nested_files_todict = {k:1 for k in pruned_nested_files}
    set_metadata(nested_files_todict, json_report, index_value)
    encoded_nested_files = pd.json_normalize(nested_files_todict, max_level=0).set_index(index_value)
    print('Processed :', json_file)
    return encoded_nested_files
  except Exception as e:
    print(f'Nested File Operations {category} KEY ERROR', e)


def get_pe_entropy(json_file, index_value = 'md5'):
  '''This function retrieves PE entropy features from json report.'''
  try:
    print('Processing :', json_file)
    json_report =  json_to_dict(json_file)
    pe_entropy = json_report['pe_analysis']['pe_entropy']
    pe_entropy_values = {k:v for k,v in zip(pe_entropy['names'], pe_entropy['entropy_values'])}
    set_metadata(pe_entropy_values, json_report, index_value)
    encoded_pe_entropy = pd.json_normalize(pe_entropy_values, max_level=0).set_index(index_value)
    print('Processed :', json_file)
    return encoded_pe_entropy
  except Exception as e:
    print('pe_entropy KEY ERROR', e)



def parallelize_process(process, args, star=True):
    '''This function allows using multiprocessing for data extraction.'''
    one_line_dataframes = []

    try:
        pool = Pool()
        if star == True:
            one_line_dataframes = pool.starmap(process, zip(*args))
        else:
            one_line_dataframes = pool.map(process, args)
        pool.close()
        pool.join()
    except Exception as e:
        print('Parallelizing process failed', e)

    return one_line_dataframes



def parallelize_concatenation(dfs, result_path=None, pickled=False, compression=None, nan_value = 0):
    '''This function allows using multiprocessing for data concatenation of multiple one line dataframes.'''
    dfs_groupings = []
    
    try:
        for i in range(cpu_count()):
            grouping = [dfs[j] for j in range(len(dfs)) if j % cpu_count() == i]
            if len(grouping) > 0:
                dfs_groupings.append(grouping)

        pool = Pool()
        concatenated_subsets = pool.map(pd.concat, dfs_groupings)
        pool.close()
        pool.join()

        complete_df = pd.concat(concatenated_subsets, axis=0, ignore_index=False).replace(np.nan, nan_value).astype(np.int32) #remove if not one-hot
        if result_path is not None:
            if pickled:
                complete_df.to_pickle(result_path, compression=compression)
            else:
                complete_df.to_csv(result_path)
        else:
            return complete_df

    except Exception as e:
        print('Concatenating dataframes failed', e)
        return pd.DataFrame()
    


def main():

    all_datasets = dict()

    #get the extracted json files list
    json_files_path = os.path.join(os.getcwd(), 'extracted')
    json_files_list = get_file_list(json_files_path, extensions=['json'])

    processing_elements = {
         'apistats_counts.pkl' : [get_encoded_apistats, False],
         'fileops_created_nested_files.pkl' : [get_nested_fileops, 'file_created'],
         'fileops_deleted_nested_files.pkl' : [get_nested_fileops, 'file_deleted'],
         'fileops_exists_nested_files.pkl' : [get_nested_fileops, 'file_exists'],
         'fileops_failed_nested_files.pkl' : [get_nested_fileops, 'file_failed'],
         'fileops_opened_nested_files.pkl' : [get_nested_fileops, 'file_opened'],
         'fileops_read_nested_files.pkl' : [get_nested_fileops, 'file_read'],
         'fileops_recreated_nested_files.pkl' : [get_nested_fileops, 'file_recreated'],
         'fileops_written_nested_files.pkl' : [get_nested_fileops, 'file_written'],
         'fileops_summary.pkl' : [get_file_operations_counts, None],
         'loaded_dll_onehot.pkl' : [get_encoded_dll_loaded, None],
         'pe_entropy_analysis.pkl' : [get_pe_entropy, None],
         'pe_imports_advapi32.pkl' : [get_encoded_pe_imports, 'advapi32.dll'],
         'pe_imports_comctl32.pkl' : [get_encoded_pe_imports, 'comctl32.dll'],
         'pe_imports_gdi32.pkl' : [get_encoded_pe_imports, 'gdi32.dll'],
         'pe_imports_kernel32.pkl' : [get_encoded_pe_imports, 'kernel32.dll'],
         'pe_imports_msvcrt.pkl' : [get_encoded_pe_imports, 'msvcrt.dll'],
         'pe_imports_ole32.pkl' : [get_encoded_pe_imports, 'ole32.dll'],
         'pe_imports_shell32.pkl' : [get_encoded_pe_imports, 'shell32.dll'],
         'pe_imports_user32.pkl' : [get_encoded_pe_imports, 'user32.dll'],
         'pe_imports_libraries.pkl' : [get_encoded_pe_imports, None],
         'regkeys_deleted_nested_keys.pkl' : [get_nested_regkeys, 'regkey_deleted'],
         'regkeys_opened_nested_keys.pkl' : [get_nested_regkeys, 'regkey_opened'],
         'regkeys_read_nested_keys.pkl' : [get_nested_regkeys, 'regkey_read'],
         'regkeys_written_nested_keys.pkl' : [get_nested_regkeys, 'regkey_written'],
         'regkeys_summary.pkl' : [get_regkeys_counts, None ]
         }

    start = time.time()

    for target, elements in processing_elements.items():
        
        start = time.time()
        print('Processing :', target)

        star = False
        args = json_files_list

        if elements[1] is not None:
            star = True
            args = (json_files_list, repeat(elements[1]))
        
        #extract data and put into a one line dataframe for each file
        dfs = parallelize_process(elements[0], args, star=star)

        print('Processing took : {} s'.format(time.time()-start))

        #concatenate the resulting one line dataframes in one dataframe and append
        result_df = parallelize_concatenation(dfs)
        if not result_df.empty:
            all_datasets[target] = result_df

        #save results
        result_path =  os.getcwd() + os.sep + 'datasets/' + target + '.gz'
        result_df.to_pickle(result_path, compression='gzip')

        print('Concatenation and saving file took : {} s'.format(time.time() - start))




if __name__ == '__main__':
    main()