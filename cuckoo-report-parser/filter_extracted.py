import json
import glob2
import os
import time

statistics = { 'goodware' : { 'missing_api_calls' : 0 },
               'malware' : { 'missing_api_calls' : 0 }}


def read_json_file(file_path):
    with open(file_path, 'rb') as f:
        json_content = json.load(f)
    return json_content


def check_json_file(file_path, statistics):
    json_file_content = read_json_file(file_path)
    file_subclass = json_file_content['file_class']['subclass_label']
    is_api_missing = json_file_content['api_calls']['is_missing']
    if file_subclass == 0:
        statistics['goodware']['missing_api_calls'] += is_api_missing
    if file_subclass == 1:
        statistics['malware']['missing_api_calls'] += is_api_missing


def get_file_list(folder_path, extensions =['zip']):
    ''' Returns the list of files with all given extensions inside the specified folder in the current working directory, '''
    file_list = []
    for extension in extensions:
        file_list.extend(glob2.glob(os.path.join(folder_path, '*.' + extension)))
    return file_list


def main():  
    folder_path = os.getcwd() + os.sep + 'extracted'
    json_files = get_file_list(folder_path, ['json'])
    for json_file in json_files:
        check_json_file(json_file, statistics)
    print(statistics)

if __name__ == '__main__':
    main()
