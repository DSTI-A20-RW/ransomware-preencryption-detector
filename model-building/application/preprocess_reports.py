import os
import zipfile
import time
import orjson
from datetime import datetime
from itertools import repeat
from multiprocessing import Pool, cpu_count, current_process


IS_GOODWARE = 0
IS_MALWARE = 1
IS_RANSOMWARE = 0


def set_file_class():
    '''Sets the class and subclass of the file which report is being processed
       @input :     None ( The return value is determined by global variables )
       @return :    dict { "class" : _ , "subclass" : _ }'''
    class_ = {}
    if IS_GOODWARE:
        class_['class'] = 'goodware'
        class_['subclass'] = 'goodware'
    if IS_MALWARE:
        class_['class'] = 'malware'
        if IS_RANSOMWARE:
            class_['subclass'] = 'ransomware'
        else:
            class_['subclass'] = 'unspecified'
    return class_


'''This finction sets an encoded label where 'malware' is class with label 1, 
ransomware subclass - 2 '''
def set_encoded_label(file_class):
    class_label = 0
    subclass_label = 0
    if file_class['class'] == 'malware':
        class_label = 1
        subclass_label = 1
    if file_class['subclass'] == 'ransomware':
        subclass_label = 2
    file_class['class_label'] = class_label
    file_class['subclass_label'] = subclass_label
    return file_class


'''this function retrieves antivirus information from json reports'''
def extract_antivirus_analysis(a_signature):
    extracted_antivirus = {}
    try:
        marks = a_signature['marks']
        categories = []
        ioc = [] #indicator of compromise
        for a_mark in marks:
            categories.append(a_mark['category'])
            ioc.append(a_mark['ioc'])
        extracted_antivirus['antivirus_list'] = categories
        extracted_antivirus['ioc_list'] = ioc
    except Exception as ex:
        print('process_signature_marks error', ex)
    return extracted_antivirus

'''this function extracts metadata such as severitym description,
 antivirus count'''
def extract_engine_analysis(a_signature):
    engine_analysis = {}
    try :
        engine_analysis['severity'] = a_signature['severity']
        engine_analysis['description'] = a_signature['description']
        engine_analysis['antivirus_count'] = a_signature['markcount']
        engine_analysis.update(extract_antivirus_analysis(a_signature))
    except Exception as ex:
        print('process_signatures_marks error', ex)
    return engine_analysis


'''this function compares scores of severity to set a treshold of an acceptable or unacceptable risk'''
def is_engine_analysis(a_signature):
    threat_detection_engines = ['antivirus', 'virustotal', 'suricata', 'irma', 'sysmon']
    is_engine_analysis_ = False
    try :
        is_severe = ( int(a_signature['severity']) >= 3 )
        contains_engine = any(engine in a_signature['description'].lower() for engine in threat_detection_engines)
        is_engine_analysis_ = ( is_severe and contains_engine )
    except Exception as ex:
        print('process_signatures_severity error', ex)
    return is_engine_analysis_


'''this function dynamically assigns names to keys'''
def change_key_name(key, dict):
    i = 0
    while key in dict:
        i += 1
        key = key + '#' + str(i)
    return key


'''this function is handking missing values case in data retrieving '''
def process_signatures(report_json):
    extracted_engine_analysis = {'is_missing' : 0}   
    try:
        signatures = report_json['signatures']
        for a_signature in signatures:
            if is_engine_analysis(a_signature) :
                engine_analysis = extract_engine_analysis(a_signature)
                engine_name = a_signature['name']
                if engine_name in extracted_engine_analysis:
                     engine_name = change_key_name(engine_name, extracted_engine_analysis)
                extracted_engine_analysis[engine_name] = engine_analysis
            else :
                extracted_engine_analysis['is_missing'] = 1
    except Exception as ex:
        #print('process_signatures error', ex)
        extracted_engine_analysis['is_missing'] = 1
    return extracted_engine_analysis

''' this function adds summary  '''
def fetch_summary(report_json):
    try:
        return report_json['behavior']['summary']     
    except Exception as ex:
        #print('fetch_summmary error', ex)
        pass
''' process behaviour feature'''
def process_behavior_files(report_json):
    extracted_files = {'is_missing' : 0}
    try:
        summary = fetch_summary(report_json)
        files_values = {}
        files_counts = {}
        for key, values_list in summary.items() :
            if str(key).startswith('file'):
                files_values[key] = values_list
                files_counts[key] = len(values_list)
        extracted_files['files_counts'] = files_counts
        extracted_files['files_values'] = files_values      
    except Exception as ex:
        #print('process_files error', ex)
        extracted_files['is_missing'] = 1
    return extracted_files

'''this function processes regkkeys from  behaviour structure json'''
def process_behavior_regkeys(report_json):
    extracted_regkeys = {'is_missing' : 0}
    try:
        summary = fetch_summary(report_json)
        regkey_values = {}
        regkey_counts = {}
        for key, values_list in summary.items() :
            if str(key).startswith('regkey'):
                regkey_values[key] = values_list
                regkey_counts[key] = len(values_list)
        extracted_regkeys['regkey_counts'] = regkey_counts
        extracted_regkeys['regkey_values'] = regkey_values        
    except Exception as ex:
        #print('process_regkeys error', ex)
        extracted_regkeys['is_missing'] = 1
    return extracted_regkeys

'''process dll from behaviour'''
def process_behavior_dll(report_json):
    extracted_dll = {'is_missing' : 0}
    try:
        summary = fetch_summary(report_json)
        extracted_dll['loaded_dll'] = summary['dll_loaded']      
    except Exception as ex:
        extracted_dll['is_missing'] = 1
        #print('process_loaded_dll error', ex)
    return extracted_dll

'''process PE imports'''
def process_pe_imports(pe_analysis):
    extracted_pe_imports = {}
    try:
        pe_imports = pe_analysis['pe_imports']
        for an_import_dict in pe_imports:
            dll = an_import_dict['dll'].lower()
            imports = []
            for an_import in an_import_dict['imports']:
                import_name = an_import['name']
                if import_name is not None:
                    imports.append(import_name)
            if dll in extracted_pe_imports:
                extracted_pe_imports[dll].extend(imports)
            else:
                extracted_pe_imports[dll] = imports
    except Exception as ex:
        print('process_pe_imports error', ex)
    return extracted_pe_imports

'''process PE sections - entropy'''
def process_pe_sections(pe_analysis):
    extracted_pe_entropy = {}
    try:
        pe_sections = pe_analysis['pe_sections']
        names = []
        entropy_values = []
        for a_section_dict in pe_sections:
            names.append(a_section_dict['name'])
            entropy_values.append(a_section_dict['entropy'])
        extracted_pe_entropy['names'] = names
        extracted_pe_entropy['entropy_values'] = entropy_values
    except Exception as ex:
        print('process_pe_entropy error', ex)
    return extracted_pe_entropy

'''process PE imports'''
def process_pe_analysis(report_json):
    extracted_pe = {'is_missing' : 0}
    try:
        pe_analysis = report_json['static']
        extracted_pe['pe_imports'] = process_pe_imports(pe_analysis)
        extracted_pe['imported_dll_count'] = len(extracted_pe['pe_imports'])
        extracted_pe['pe_entropy'] = process_pe_sections(pe_analysis)
    except Exception as ex:
        print('process_pe_analysis error', ex)
    return extracted_pe

'''fill missing values'''
def fill_missing(dic, key):
    if key == 'yara' :
        dic[key] = []
    elif key == 'size' :
        dic[key] = 0
    else:
        dic[key] = ''

'''process target file (json report)'''
def process_target_file(report_json, include_yara=True):
    extracted_file_info = {'is_missing' : 0}
    info_elements = ['name', 'type', 'size', 'ssdeep', 'sha256', 'sha512', 'md5']
    if include_yara :
        info_elements.append('yara')
    try:
        file = report_json['target']['file']
        for element in info_elements:
            if element in file.keys():
                extracted_file_info[element] = file[element]
            else:
                fill_missing(extracted_file_info, element)
    except Exception as ex:
        #print('process_target_file error', ex)
        extracted_file_info['is_missing'] = 1
    return extracted_file_info

'''convert to datetime format'''
def convert_to_datetime(datetime_str):
    return datetime.strptime(datetime_str, '%Y-%m-%d %H:%M:%S')

'''retrieve duration'''
def get_duration(start_time_str, end_time_str):
    start_time = convert_to_datetime(start_time_str)
    end_time = convert_to_datetime(end_time_str)
    return (end_time - start_time).total_seconds()

'''retrieve vm status'''
def process_info_machine(report_json):
    extracted_analysis = {'is_missing' : 0}
    try:
        analysis = report_json['info']['machine']
        analysis_duration = get_duration(analysis['started_on'], analysis['shutdown_on'])
        extracted_analysis['duration'] = int(analysis_duration)
        extracted_analysis['vm_status'] = analysis['status']     
    except Exception as ex:
        #print('process_info_machine error', ex)
        extracted_analysis['is_missing'] = 1
    return extracted_analysis


def update_dictionary(dic1, dic2):
  for key, value in dic2.items():
    if key in dic1:
      dic1[key] = dic1[key] + value
    else:
      dic1[key] = value
  return dic1


'''this function processes apistats from behaviour '''
def process_behavior_apistats(report_json):
    extracted_api_calls = {'is_missing' : 0}
    try:
        apistats = report_json['behavior']['apistats']
        keys = apistats.keys()
        process_count = 0
        api_calls = {}         
        for key in keys:
            process_count += 1
            process_api_calls = apistats[key]
            update_dictionary(api_calls, process_api_calls)
        extracted_api_calls['process_count'] = process_count
        extracted_api_calls['apistats'] = api_calls       
    except Exception as ex:
        #print('process_api_stats error', ex)
        extracted_api_calls['is_missing'] = 1
    return extracted_api_calls

'''this function stores each of choosed variables in a separate list'''
def process_json_file(json_file_path, result_folder_path, file_class):
    extracted = {}
    try:
        with open(json_file_path, 'r') as f:
            report_json = orjson.loads(f.read())
            extracted["file_class"] = set_encoded_label(file_class)
            extracted["file_information"] = process_target_file(report_json, include_yara=False)
            extracted["analysis_duration"] = process_info_machine(report_json)        
            extracted["api_calls"] = process_behavior_apistats(report_json)
            extracted["dll_loaded"] = process_behavior_dll(report_json)
            extracted["pe_analysis"] = process_pe_analysis(report_json) 
            extracted["file_operations"] = process_behavior_files(report_json)
            extracted["regkeys"] = process_behavior_regkeys(report_json)
            extracted["antivirus_detection"] = process_signatures(report_json) 
        
        file_name = extracted["file_class"]["class"] + '-' + extracted["file_information"]["md5"] +'.json'
        result_path = os.path.join(result_folder_path, file_name)

        with open(result_path, "wb") as f:
            f.write(orjson.dumps(extracted, option=orjson.OPT_INDENT_2))

    except Exception as e:
        print('Unable to load json file : {}'.format(json_file_path))
        print('Error:', e)

'''this function deletes original json report (as we have already extracted data)'''
def delete_json_report(json_file_path):
    os.remove(json_file_path)


'''this function unarchives zip files'''
def unzip_report(file_path):
    json_path = os.path.dirname(file_path) + os.sep
    json_file_path = os.path.splitext(file_path)[0] + '.json'
    zipfile.ZipFile(file_path, 'r').extractall(json_path)
    return json_file_path  


'''this function facilitates work with zip files'''
def process_zip_file(file_path, result_folder_path, file_class):
    #print(current_process().name,'Processing', file_path)
    start = time.time()
    json_file_path = unzip_report(file_path)
    result_path = os.path.join(result_folder_path, os.path.basename(json_file_path))
    process_json_file(json_file_path, result_folder_path, file_class)
    delete_json_report(json_file_path)
    print('{} Processed : {} \t Duration : {} s'.format(current_process().name, os.path.split(file_path)[1], time.time() - start))


'''this function reads zip files'''
def read_zip_files(root):
    files = []
    for dir_name, sub_dir_list, file_list in os.walk(root):
        for file_name in file_list:
            file_path = os.path.join(dir_name, file_name)
            if 'zip' in file_path:
                files.append(file_path)
    return files



def main():
    
    start = time.time()

    #set the file label depending on global variables
    file_class = set_file_class()
    
    #create the result folder if it doesn't exist
    result_folder_path = os.getcwd() + os.sep + 'extracted'
    if not os.path.exists(result_folder_path):
        os.mkdir(result_folder_path)
    
    #get the list of zip files in reports folder
    zip_files = read_zip_files(os.getcwd() + os.sep + 'reports')
    
    #parallelize the processing over all available cpu cores
    pool = Pool()
    pool.starmap(process_zip_file, zip(zip_files, repeat(result_folder_path), repeat(file_class)))
    pool.close()
    pool.join()

    print('Processed all {} files in : {} s'.format(len(zip_files), time.time() - start))


if __name__ == '__main__':
    main()