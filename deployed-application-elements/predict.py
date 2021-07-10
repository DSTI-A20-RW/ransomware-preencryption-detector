import pandas as pd
import numpy as np
import os
import re
import pickle


#VERSION

#python 3.8.8
#pandas 1.2.3
#numpy 1.20.2
#pickle 4.0
#sklearn 0.24.2
#xgboost 1.4.2


def clean_column_names(df):
    '''replace the characters ( '[', ']', '<' ) with ( '_' ) in column names because XGBoost doesnt accept them'''
    df = df.copy()
    regex = re.compile(r"\[|\]|<", re.IGNORECASE)
    df.columns = [regex.sub("_", col) if any(x in str(col) for x in set(('[', ']', '<'))) else col for col in df.columns.values]
    return df


def main():
    
    malware_dataset_path = os.getcwd() + os.sep + 'application/dataset/result_malware.pkl.gz'
    ransomware_dataset_path = os.getcwd() + os.sep + 'application/dataset/result_ransomware.pkl.gz'

    malware_model_path = os.getcwd() + os.sep + 'application/trained_model/model_malware.pkl'
    ransomware_model_path = os.getcwd() + os.sep + 'application/trained_model/model_ransomware.pkl'
    
    #load dataset
    malware_dataset = pd.read_pickle(malware_dataset_path, compression='gzip')
    ransomware_dataset = pd.read_pickle(ransomware_dataset_path, compression='gzip')
    
    #clean column names for XGBoost
    X_malware = clean_column_names(malware_dataset)
    X_malware = X_malware.iloc[:1,:]
    
    #load model
    malware_model = pickle.load(open(malware_model_path, 'rb'))
    
    #predict class
    label = malware_model.predict(X_malware)[0]
    file_type = 'Malware' if label==1 else 'Goodware'
    conclusion = 'Be careful, this file is dangerous!' if label==1 else 'The file is safe for download.'

    #get probability of predicted class
    malware_prob = malware_model.predict_proba(X_malware)[0][label]
    
    if label == 1:
        X_ransomware = clean_column_names(ransomware_dataset)
        X_ransomware = X_ransomware.iloc[:1,:]
        ransomware_model = pickle.load(open(ransomware_model_path, 'rb'))
        sublabel = ransomware_model.predict(X_ransomware)[0]

        if sublabel == 2:
            file_subtype = 'Ransomware'
            ransomware_prob = ransomware_model.predict_proba(X_ransomware)[0][sublabel-1]
    else:
        sublabel = 0
    
    message = f'''The file is determined to be {file_type} with {round(100*malware_prob, 2)}%.\n'''

    if sublabel == 2:
        message += f'''The file is also determined to be {file_subtype} with {round(100*ransomware_prob, 2)}%.\n'''

    message += f'''\nConclusion: {conclusion}'''
    
    #print(message)
    with open('message.txt', 'w') as f:
        f.write(message)


if __name__ == '__main__':
    main()
