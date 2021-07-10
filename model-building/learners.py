import os
import time
import re
import pandas as pd
import numpy as np
from numpy import hstack
import matplotlib
import matplotlib.pyplot as plt

from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis as LDA
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, AdaBoostClassifier, GradientBoostingClassifier
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from catboost import CatBoostClassifier

from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from keras.wrappers.scikit_learn import KerasClassifier

from sklearn.preprocessing import MinMaxScaler, StandardScaler, RobustScaler
from sklearn.feature_selection import SelectKBest, f_classif, chi2, mutual_info_classif, RFE
from sklearn.utils import shuffle
from sklearn.model_selection import KFold, StratifiedKFold, RepeatedStratifiedKFold, cross_val_score, GridSearchCV, train_test_split
from skopt import BayesSearchCV
from skopt.space import Integer, Real, Categorical
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score

from imblearn.over_sampling import SMOTE, BorderlineSMOTE, SVMSMOTE, ADASYN
from imblearn.under_sampling import RandomUnderSampler
from collections import Counter
from imblearn.pipeline import Pipeline

from helpers import *


## DATA LOADING AND PREVIEW

def prepare_datasets(datasets_path='datasets', columns_path=None, label='label', verbose=True, prefix=True):
    
    datasets = dict()
    
    #retrieve list of files
    datasets_files = get_file_list(datasets_path, extensions=['gz'])
    columns_files = get_file_list(columns_path, extensions=['pkl'])
    
    for file in datasets_files:
        
        #retrieve name corresponding to selected features file and define the full path 
        basename = os.path.splitext(os.path.basename(file))[0]
        if columns_path is not None:
            columns_file = os.path.join(columns_path, basename)
        
        #print current processed dataset
        if verbose:
            print(basename.split('.')[0])
            
        #load full dataset    
        dataset = get_data(file_path = file, compression='gzip', verbose=verbose)
        
        #subset dataset with selected features
        if len(columns_files) > 0:
            if columns_file in columns_files:
                columns = unpickle_results(columns_file)
                dataset = dataset[list(columns)+[label]]        
                #prefix column names to avoid column names overlap
                if prefix:
                    mapping = { column : basename.split('.')[0] + '_' + column for column in columns }
                    dataset.rename(columns = mapping, inplace=True)            
            #print resulted shape
            if verbose:
                print('resulted data shape :'.ljust(20), dataset.shape, '\n')
            
        #append datasets    
        datasets[basename.split('.')[0]] = dataset
        
    return datasets


def preview_data(folder_path, file_name, index_value = 'md5'):
    df = pd.read_csv(os.path.join(folder_path, file_name), index_col=index_value)
    print(f'Nb Observations: {df.shape[0]}')
    print(f'Nb Features: {df.shape[1] - 1}')
    return df.drop(['label'], axis=1).head(3)

def class_distribution(df, label='sublabel'):
    dist = df[label].value_counts()
    dist = list(zip(dist.index, dist))
    print('Class distribution:')
    for element in dist:
        label_ = 'malware'
        if element[0] == 0:
            label_ = 'goodware'
        elif element[0] == 2:
            label_ = 'ransomware'
        print(f"{label_:<12} : {element[1]}")
    try:
        print(f"\nMajority class classifier accuracy = {round(100*dist[0][1]/(dist[0][1]+dist[1][1]), 2)}%")
    except:
        print("Warning: There's only one class. Consider changing label to sublabel.")

def print_proportion(df, label = 'label'):
    print('Proportion : {:.2f}%'.format(100*sum(df.label)/len(df)))


## SMOTE  
    

def smote(X, y, category ='smote', over_strategy=None, under_strategy=None, k_neighbors=5, fit=True):
    X = X.copy()
    y = y.copy()
    smoters = {
        'smote' : SMOTE(sampling_strategy=over_strategy, k_neighbors=k_neighbors),
        'borderline' : BorderlineSMOTE(sampling_strategy=over_strategy, k_neighbors=k_neighbors),
        'svm' : SVMSMOTE(sampling_strategy=over_strategy, k_neighbors=k_neighbors),
        'adaptive' : ADASYN(sampling_strategy=over_strategy, n_neighbors=k_neighbors),
    }
    steps = []
    if over_strategy is not None:        
        over = smoters[category]
        steps.append(('over', over))
    if under_strategy is not None:
        under = RandomUnderSampler(sampling_strategy=under_strategy)
        steps.append(('under', under))
    if fit:
        pipe = Pipeline(steps=steps)
        X, y = pipe.fit_resample(X, y)
        result = X, y
    else:
        result = steps
    return result


def print_new_distribution(X, y, smote_params):
    X, y = smote(X, y, **smote_params, fit=True)
    counter = dict(Counter(y))
    counter['malware'] = counter.pop(1)
    counter['ransomware'] = counter.pop(2)
    print(f'The new class distribution after SAMPLING strategy : {counter}')



## MODEL SELECTION   
    
    
def create_regular_net():
    model = Sequential()
    model.add(Dense(units=10, kernel_initializer = 'uniform', activation = 'relu', name='dense_layer1'))
    model.add(Dense(units=10, kernel_initializer = 'uniform', activation = 'relu', name='dense_layer2'))
    model.add(Dense(1, activation = 'sigmoid', name = 'dense_output'))   #sigmoid for binary 
    model.compile(loss='binary_crossentropy', optimizer= 'adam', metrics = ['accuracy'])
    return model


def wrap_regular_net():
    model = KerasClassifier(build_fn=create_regular_net, epochs=50, batch_size=64, verbose=0)
    return model


def create_models():
    models = dict()
    models['LogisticRegression'] = LogisticRegression(solver='sag')
    models['KNN'] = KNeighborsClassifier()
    models['Decision tree'] = DecisionTreeClassifier()
    models['Random Forest'] = RandomForestClassifier()
    #models['Stochastic Gradient Descent'] = SGDClassifier()
    models['SVM'] = SVC()
    models['RegularNets'] = wrap_regular_net()
    models['LDA'] = LDA()
    models['Gaussian Naive Bayes'] = GaussianNB()
    return models
    
    
def create_X_y(folder_path, file_name, drop_null_columns=False, index_value = 'md5'):
    file_path = os.path.join(folder_path, file_name)
    df = pd.read_csv(file_path, index_col = index_value)
    X = df.drop('label', axis=1)
    #X = df.drop(['label', 'sublabel'], axis=1)
    if drop_null_columns == True:
        X = X.drop(get_null_columns(X), axis=1)
    y = df['label']
    return shuffle(X, y)


def get_X_y(df, drop_null_columns=False, index_value = 'md5', label='label'):
    label_columns = []
    if 'label' in df.columns:
        label_columns.append('label')
    if 'sublabel' in df.columns:
        label_columns.append('sublabel')
    X = df.drop(label_columns, axis=1)
    if drop_null_columns == True:
        X = X.drop(get_null_columns(X), axis=1)
    y = df[label]
    return shuffle(X, y)


def evaluate_model(model, X, y, scoring='accuracy'):
    cv = RepeatedStratifiedKFold(n_splits=10, n_repeats=3, random_state=2)
    scores = cross_val_score(model, X, y, scoring=scoring, cv=cv, n_jobs=-1, error_score='raise')
    return scores


def get_evaluation_results(df=None, folder_path=None, file_name=None, drop_null_columns=False, label='label', scoring='accuracy', smoter=None, selector=None, scaler=None, rename=None, limit=None, subset=None):  
    
    #generate features and target
    if df is not None:
        X, y = get_X_y(df, label=label)
    else:
        X, y = create_X_y(folder_path, file_name, drop_null_columns)
    
    if subset is not None:
        X = X[subset]
    if rename is not None:
        X = X.rename(columns=rename)
    if limit is not None:
        X = X.iloc[:,:limit]
            
    #generate models
    models = create_models()
    
    #evaluate models and store results
    results, names = list(), list()
    for name, model in models.items():
        steps = []
        if smoter is not None and isinstance(smoter, list):
            steps.extend(smoter)
        if scaler is not None:
            steps.append(('scaler', scaler))
        if selector is not None:
            steps.append(('selector', selector))
        steps.append(('classifier', model))
        pipeline = Pipeline(steps=steps)
        scores = evaluate_model(pipeline, X, y, scoring=scoring)
        results.append(scores)
        names.append(name) 
        
    return names, results


def print_evaluation_results(results, names):  
    for name, scores in zip(names, results):
        print(f"{name:30} \t: {np.mean(scores)*100:.3f}% ( (+/-) {np.std(scores)*100:.3f}% )")  



## FEATURE SELECTION

def get_most_recurrent(df, portion=0.05, limit=None):
    if limit is None:
        limit = int(portion*len(df.columns))
    most_recurrent_ = df.drop(['label', 'sublabel'], axis=1).sum().sort_values(ascending=False).iloc[:limit]
    return most_recurrent_


def select_k_best(df, select_function=f_classif, k=10, label='label', smoter=None):
    X, y = get_X_y(df, label=label)
    steps = []
    if smoter is not None:
        steps.extend(smoter)
    selector = SelectKBest(select_function, k=k)
    steps.append(('selector', selector))
    pipe = Pipeline(steps=steps)
    pipe.fit(X, y)
    selected_columns_indices = pipe['selector'].get_support(indices=True)
    selected_df = X.iloc[:,selected_columns_indices]
    selected_columns = selected_df.columns.tolist()
    return selected_columns


def get_feature_importances(X, y, model=RandomForestClassifier(), limit=None):
    model.fit(X,y)
    fi = model['classifier'].feature_importances_
    sorted_fi_idx = np.argsort((-1)*fi)
    if limit is not None:
        sorted_fi_idx = sorted_fi_idx[:limit]
    return X.columns[sorted_fi_idx], fi[sorted_fi_idx]


def search_feature_importances(df, k_values, model=RandomForestClassifier(), scoring='accuracy', verbose=False, label='label'):
    all_scores = dict()
    scores_summary = dict()
    X, y = get_X_y(df, label=label)
    columns, feature_importances = get_feature_importances(X, y, model=model)  
    for k in k_values:
        top_k_columns = columns[:k]
        scores = evaluate_model(model=model, X=X[top_k_columns], y=y, scoring=scoring)
        all_scores[k] = scores
        scores_summary[k] = [round(np.median(scores)*100, 2), round(np.std(scores)*100, 2)]
        if verbose:
            print(f"k={k} \t: {scoring} = {scores_summary[k][0]}% ( (+/-) {scores_summary[k][1]}% )")
    best = sorted(list(scores_summary.items()), key=lambda x:x[1][0], reverse=True)[0]
    print(f"\nBest value : k = {best[0]} --> {scoring} = {best[1][0]}% ( (+/-) {best[1][1]}% )")
    return all_scores, scores_summary


def summaries_to_df(summaries, k_range, path='selected-features/k-search-summary', file=None):
    result = pd.DataFrame(index=k_range)
    for category, summary in summaries.items():
        summary_str = {k: f"{v[0]}% (+/- {v[1]}%)" for k,v in summary.items()}
        summary_df = pd.DataFrame.from_dict(summary_str, orient='index', columns=[category])
        result = result.join(summary_df)
    if file is not None:
        file_path = os.path.join(path, file)
        result.to_csv(file_path)
    return result


def save_selected_features(df, k, model=RandomForestClassifier(), path='selected-features', file='untitled.pkl', prefix=None, preview=None, label='label'):
    X, y = get_X_y(df, label=label)
    columns, feature_importances = get_feature_importances(X, y, model=model)
    top_k_columns = columns[:k]
    if prefix is not None:
        pickle_results(top_k_columns, file=file, path=path+'/unprefixed')
        top_k_columns = [prefix + '__' + column for column in top_k_columns]
    pickle_results(top_k_columns, file=file, path=path)
    if preview is not None and isinstance(preview, int):
        plt.figure(figsize=(14,int(preview/4)))
        plt.barh(columns[:preview][::-1], feature_importances[:preview][::-1])
        plt.title('Preview of Features with the Highest Feature Importance')
        plt.show()
        

        
## JOINING and BLENDING        

def score_model_dataset(df, model, execution_time=False, label='label'):
    X, y = get_X_y(df, label=label)
    start = time.time()
    scores = evaluate_model(model, X, y)
    result = scores
    if execution_time == True:
        duration = time.time() - start
        result = scores, duration
    return result


def join_dfs(dfs, labels=['label'], initialization=None):
    if initialization is None:
        sorted_dfs = sorted(dfs, key=lambda df:len(df), reverse=True)
        initialization = sorted_dfs[0][labels[0]]
    joined = pd.DataFrame(initialization)
    for df in dfs:
        joined = joined.join(df.drop(labels, axis=1)).fillna(0)
    return joined


def retrieve_subset(original_df, X, y = None, label='label', features_only=False):
    filtered_columns = original_df.columns.tolist()
    filtered_columns.remove(label)
    if features_only == False :
        filtered_index = original_df.index.intersection(X.index)
        X_new = X.loc[filtered_index, filtered_columns]
        y_new = y.loc[filtered_index]
        return X_new, y_new
    else :
        X_new = X.loc[:, filtered_columns]
        return X_new
    
    
def prepare_training_datasets(original_dfs, X_train_full, X_test, y_train_full, y_test, test_size = 0.4, label='label'):
    datasets = []
    X_train, X_eval, y_train, y_eval = train_test_split(X_train_full, y_train_full, test_size = test_size, random_state = 1)
    for df in original_dfs:
        dataset = dict()
        dataset['train'] = retrieve_subset(df, X_train, y_train, label=label)
        dataset['eval'] = ( retrieve_subset(df, X_eval, features_only=True, label=label), y_eval )
        dataset['test'] = ( retrieve_subset(df, X_test, features_only=True, label=label), y_test )
        datasets.append(dataset)
    return datasets
    
    
def fit_ensemble(models, datasets):
    X_meta = list()
    for model, dataset in zip(models, datasets):
        model.fit(*dataset['train'])
        y_pred = model.predict(dataset['eval'][0])
        y_pred = y_pred.reshape(len(y_pred), 1)
        X_meta.append(y_pred)
    X_meta = np.hstack(X_meta)
    blender = LogisticRegression()
    blender.fit(X_meta, dataset['eval'][1])
    return blender


def predict_ensemble(models, blender, datasets):
    X_meta = list()
    for model, dataset in zip(models, datasets):
        y_pred = model.predict(dataset['test'][0])
        y_pred = y_pred.reshape(len(y_pred), 1)
        X_meta.append(y_pred)
    X_meta = np.hstack(X_meta)
    return blender.predict(X_meta)


def get_blender_accuracy(original_dfs, X_train_full, X_test, y_train_full, y_test, models, label='label'):
    datasets = prepare_training_datasets(original_dfs, X_train_full, X_test, y_train_full, y_test, test_size = 0.4, label=label)
    blender = fit_ensemble(models, datasets)
    y_pred = predict_ensemble(models, blender, datasets)
    accuracy = accuracy_score(y_test, y_pred)
    return accuracy


        
        
## HYPERPARAMETER TUNING

@timed
def hyperparameter_tuning(X_train, y_train, model, tuning_params, scoring='accuracy', cv_strategy=None, n_iterations = 25, verbose=True, folder_name='default', best_model=False):

    bsearch = BayesSearchCV(estimator = model,
                            search_spaces = tuning_params,                        
                            scoring = scoring,
                            cv = cv_strategy,
                            n_jobs = -1,
                            verbose = 0,
                            random_state = 1,
                            n_iter = n_iterations)
    
    
    def status_print(optim_result):
        """Status callback durring bayesian hyperparameter search"""

        # Get all the models tested so far in DataFrame format
        all_models = pd.DataFrame(bsearch.cv_results_)    

        # Get current parameters and the best parameters    
        best_params = pd.Series(bsearch.best_params_)
        if verbose == True:
                print('Model #{}\nBest {}: {}\nBest params: {}\n'.format(
                len(all_models),
                scoring.upper(),
                np.round(bsearch.best_score_, 4),
                bsearch.best_params_
                ))

        # Save all model results
        clf_name = bsearch.estimator.__class__.__name__
        folder_path = os.path.join("bayes-search-models", folder_name)
        all_models.to_csv(os.path.join(folder_path, clf_name+"_cv_results.csv"))
   
    bsearch.fit(X_train,y_train, callback=status_print)

    result = bsearch.best_params_
    
    if best_model == True:
        result = bsearch.best_params_, bsearch.best_estimator_
    
    return result


## NESTED CROSS-VALIDATION


def get_ensemble_models_():
    models = dict()
    models['RF'] = RandomForestClassifier()
    models['ExRF'] = ExtraTreesClassifier()
    models['AdaBoost'] = AdaBoostClassifier(base_estimator=DecisionTreeClassifier(max_depth=2), n_estimators=500)
    models['GB'] = GradientBoostingClassifier()
    models['XGBoost'] = XGBClassifier(objective = 'binary:logistic', eval_metric = 'logloss', silent=1, tree_method='approx')
    models['LightGBM'] = LGBMClassifier(objective='binary', metric='binary_logloss', verbose=0)
    #models['CatBoost'] = CatBoostClassifier(thread_count=2, loss_function='Logloss', od_type = 'Iter', verbose= False)
    return models

def clean_column_names(df):
    '''replace the characters ( '[', ']', '<' ) with ( '_' ) in column names because XGBoost doesnt accept them'''
    df = df.copy()
    regex = re.compile(r"\[|\]|<", re.IGNORECASE)
    df.columns = [regex.sub("_", col) if any(x in str(col) for x in set(('[', ']', '<'))) else col for col in df.columns.values]
    #df = df.rename(columns = lambda x:re.sub('[^A-Za-z0-9_]+', '', x))
    return df
    
def get_pipeline(clf, scaler=None, selector=None):
    steps = []
    if scaler is not None:
        steps.append(('scaler', scaler))
    if selector is not None:
        steps.append(('selector', selector))
    steps.append(('clf', clf))
    return Pipeline(steps=steps)
    
def print_mean_std(scores, model_name, execution_time=None):
    if execution_time is not None:
        print(f'{model_name:<14}: {round(100*np.mean(scores), 2)}% ( +/- {round(100*np.std(scores), 2)}% ) -- [ {round(execution_time, 2)}s ]')
    else:
        print(f'{model_name:<14}: {round(100*np.mean(scores), 2)}% ( +/- {round(100*np.std(scores), 2)}% )')
        
        
        
@timed
def perform_nested_cv(df, cv_results_path='apistats_accuracy_30', scoring='accuracy', n_iterations=30):
    
    cv_outer = StratifiedKFold(n_splits=10, shuffle=True, random_state=1)

    outer_results = { name : [] for name in tuning_params.keys()}

    X, y = create_X_y_(df)

    for train_ix, test_ix in cv_outer.split(X, y) :

        X_train, X_test = X.iloc[train_ix, :], X.iloc[test_ix, :]
        y_train, y_test = y[train_ix], y[test_ix]

        cv_inner = StratifiedKFold(n_splits=3, shuffle=True, random_state=1)

        ensemble_models = get_ensemble_models()

        for name, model in ensemble_models.items():

            try:
                best_params, best_model = hyperparameter_tuning(X_train = X_train, 
                                                                y_train = y_train, 
                                                                model = model, 
                                                                tuning_params = tuning_params[name], 
                                                                scoring = scoring, 
                                                                cv_strategy = cv_inner, 
                                                                n_iterations = n_iterations,
                                                                verbose = True,
                                                                folder_name = cv_results_path,
                                                                best_model = True)


                y_pred = best_model.predict(X_test)

                acc = accuracy_score(y_test, y_pred)
            
            except Exception as e:
                acc = 0
                print('ERROR '+name+' :', e)

            outer_results[name].append(acc)

    try:
        pickle_results(outer_results, cv_results_path+'.pickle')
    except Exception as e :
        print('ERROR: Unpickling unsuccessful!')
    
    return outer_results