import pandas as pd
import numpy as np
import os
import re
import pickle


def clean_column_names(df):
    '''replace the characters ( '[', ']', '<' ) with ( '_' ) in column names because XGBoost doesnt accept them'''
    df = df.copy()
    regex = re.compile(r"\[|\]|<", re.IGNORECASE)
    df.columns = [regex.sub("_", col) if any(x in str(col) for x in set(('[', ']', '<'))) else col for col in df.columns.values]
    return df


def main():
    
    dataset_path = os.getcwd() + os.sep + 'dataset/result.pkl.gz'
    model_path = os.getcwd() + os.sep + 'trained-model/model.pkl'
    
    #load dataset
    dataset = pd.read_pickle(dataset_path, compression='gzip')
    
    #clean column names for XGBoost
    X = clean_column_names(dataset)
    X = X.iloc[:1,:]
    
    #load model
    model = pickle.load(open(model_path, 'rb'))
    
    #predict class
    label = model.predict(X)[0]
    file_type = 'Malware' if label==1 else 'Goodware'
    message = 'Be careful, this file is dangerous!' if label==1 else 'The file is safe for download.'
    
    #get probability of predicted class
    prob = model.predict_proba(X)[0][label]
    
    #print result
    print(f'The file is determined to be {file_type} with {round(100*prob, 2)}%. \n\nConclusion: {message}')


if __name__ == '__main__':
    main()