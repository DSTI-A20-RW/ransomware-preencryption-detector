import os
import time
import json
import orjson
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
  with open(json_file, 'r') as f:
    json_report = orjson.loads(f.read())
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


def set_metadata(selection, json_report, index_value): 
  selection[index_value] = get_index(json_report, index_value)
  selection['label'] = get_label(json_report, 'class')
  selection['sublabel'] = get_label(json_report, 'subclass')


def get_encoded_apistats(json_file, one_hot = False, index_value = 'md5'):
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



def get_encoded_dll_loaded(json_file, index_value = 'md5'):
  try:
    print('Processing :', json_file)
    json_report =  json_to_dict(json_file)
    dll_loaded = json_report['dll_loaded']['loaded_dll']
    dll_loaded_todict = { dll : 1 for dll in dll_loaded }
    set_metadata(dll_loaded_todict, json_report, index_value)
    encoded_dll_loaded = pd.json_normalize(dll_loaded_todict, max_level=0).set_index(index_value)
    print('Processed :', json_file)
    return encoded_dll_loaded
  except Exception as e:
    print('dll_loaded KEY ERROR', e)



def get_file_operations_counts(json_file, index_value = 'md5'):
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


def get_pe_entropy(json_file, index_value = 'md5'):
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



def parallelize_concatenation(dfs, result_path, nan_value = 0):
    
    dfs_groupings = []
    
    for i in range(cpu_count()):
        grouping = [dfs[j] for j in range(len(dfs)) if j % cpu_count() == i]
        if len(grouping) > 0:
            dfs_groupings.append(grouping)

    try:
        pool = Pool()
        concatenated_subsets = pool.map(pd.concat, dfs_groupings)
        pool.close()
        pool.join()
    except Exception as e:
        print('Parallelizing concatenation failed', e)

    try:
        complete_df = pd.concat(concatenated_subsets, axis=0, ignore_index=False).replace(np.nan, nan_value).astype(np.int32) #remove if not one-hot
        complete_df.to_csv(result_path)
    except Exception as e:
        print('Concatenating dataframes failed', e)
    



def main_api_stats():
    
    json_files_path = os.path.join(os.getcwd(), 'extracted')
    json_files_list = get_file_list(json_files_path, extensions=['json'])

    start = time.time()

    one_hot = False
    args = (json_files_list, repeat(one_hot))
    dfs = parallelize_process(get_encoded_apistats, args)

    print('Processing took : {} s'.format(time.time()-start))

    result_path = os.getcwd() + os.sep + 'count_encoded_ransom_dataset.csv'
    parallelize_concatenation(dfs, result_path)

    print('Concatenation and saving file took : {} s'.format(time.time() - start))


def main_dlls():
    
    json_files_path = os.path.join(os.getcwd(), 'extracted')
    json_files_list = get_file_list(json_files_path, extensions=['json'])

    start = time.time()

    dfs = parallelize_process(get_encoded_dll_loaded, json_files_list, star=False)

    print('Processing took : {} s'.format(time.time()-start))

    result_path = os.getcwd() + os.sep + 'onehot_encoded_dll_ransom_dataset.csv'
    parallelize_concatenation(dfs, result_path)

    print('Concatenation and saving file took : {} s'.format(time.time() - start))
    

def main_file_operations():
    
    json_files_path = os.path.join(os.getcwd(), 'extracted')
    json_files_list = get_file_list(json_files_path, extensions=['json'])

    start = time.time()

    dfs = parallelize_process(get_file_operations_counts, json_files_list, star=False)

    print('Processing {} files took : {} s'.format(len(json_files_list), time.time()-start))

    result_path = os.getcwd() + os.sep + 'file_operations_counts_ransom_dataset.csv'
    parallelize_concatenation(dfs, result_path)

    print('Concatenation and saving file took : {} s'.format(time.time() - start))



def main_regkeys():
    
    json_files_path = os.path.join(os.getcwd(), 'extracted')
    json_files_list = get_file_list(json_files_path, extensions=['json'])

    start = time.time()

    dfs = parallelize_process(get_regkeys_counts, json_files_list, star=False)

    print('Processing {} files took : {} s'.format(len(json_files_list), time.time()-start))

    result_path = os.getcwd() + os.sep + 'regkeys_counts_ransom_dataset.csv'
    parallelize_concatenation(dfs, result_path)

    print('Concatenation and saving file took : {} s'.format(time.time() - start))


def main_pe_entropy():
    
    json_files_path = os.path.join(os.getcwd(), 'extracted')
    json_files_list = get_file_list(json_files_path, extensions=['json'])

    start = time.time()

    dfs = parallelize_process(get_pe_entropy, json_files_list, star=False)

    print('Processing {} files took : {} s'.format(len(json_files_list), time.time()-start))

    result_path = os.getcwd() + os.sep + 'pe_entropy_ransom_dataset.csv'
    parallelize_concatenation(dfs, result_path)

    print('Concatenation and saving file took : {} s'.format(time.time() - start))



def main_dll():
    
    json_files_path = os.path.join(os.getcwd(), 'extracted')
    json_files_list = get_file_list(json_files_path, extensions=['json'])

    dll_names = ['kernel32.dll',
                 'user32.dll',
                 'msvcrt.dll',
                 'ole32.dll',
                 'shell32.dll',
                 'oleaut32.dll',
                 'comctl32.dll',
                 'comdlg32.dll',
                 'winmm.dll',
                 'ntdll.dll']

    for dll_name in dll_names:

        start = time.time()

        args = (json_files_list, repeat(dll_name))
        dfs = parallelize_process(get_encoded_pe_imports, args)
        
        #dfs = parallelize_process(get_encoded_pe_imports, json_files_list, star=False)
            
        print('Processing {} files took : {} s'.format(len(json_files_list), time.time()-start))

        result_path = os.getcwd() + os.sep + 'encoded_' + dll_name.split('.')[0] + '_pe_imports_dataset.csv'
        #result_path = os.getcwd() + os.sep + 'encoded_pe_imports_dll_libraries_dataset.csv'
        parallelize_concatenation(dfs, result_path)

        print('Concatenation and saving file took : {} s'.format(time.time() - start))


def is_ransomware(json_file, total, result_folder_path):
    try:
        print('Processing :', json_file)
        json_report =  json_to_dict(json_file)
        antivirus = json_report['antivirus_detection']
        is_ransomware_ = 0
        for key in antivirus.keys():
            if 'antivirus' in key:
                for element in antivirus[key]['ioc_list']:
                    for keyword in ['virlock', 'rnsm', 'ransom', 'cryptik', 'kryptik']:
                        if keyword in element.lower():
                            is_ransomware_+= 1
        if is_ransomware_ > 0:
            total.append(json_file)
            json_report['file_class']['subclass'] = 'ransomware'
            json_report['file_class']['subclass_label'] = '2'

        result_file_path = os.path.join(result_folder_path, os.path.basename(json_file))

        with open(result_file_path, "wb") as f:
            f.write(orjson.dumps(json_report, option=orjson.OPT_INDENT_2))

        print('Processed :', json_file, ' with ', is_ransomware_)
    except Exception as e:
        print('antivirus KEY ERROR', e)




def detecting_ransomware():
    
    json_files_path = os.path.join(os.getcwd(), 'extracted')
    json_files_list = get_file_list(json_files_path, extensions=['json'])

    total = []

    result_folder_path = os.path.join(os.getcwd(), 'modified')
    if not os.path.exists(result_folder_path):
        os.mkdir(result_folder_path)

    for json_file in json_files_list:
        is_ransomware(json_file, total, result_folder_path)

    print("Total ransomware {} from {}".format(len(total), len(json_files_list)))
    #print(total)



if __name__ == '__main__':
    main()