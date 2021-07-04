import os
import time
import re
import pandas as pd
import numpy as np
from numpy import hstack
import matplotlib
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, AdaBoostClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from catboost import CatBoostClassifier

from sklearn.preprocessing import MinMaxScaler, StandardScaler, RobustScaler
from sklearn.feature_selection import SelectKBest, f_classif, chi2, mutual_info_classif
from sklearn.utils import shuffle
from sklearn.model_selection import KFold, StratifiedKFold, RepeatedStratifiedKFold, cross_val_score, GridSearchCV, train_test_split
from skopt import BayesSearchCV
from skopt.space import Integer, Real, Categorical
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score


from helpers import *


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
    label_columns = ['label']
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

def k_best_selection_(X, y, select_function=f_classif, k=10):
    selector = SelectKBest(select_function, k=k).fit(X, y)
    selected_columns_indices = selector.get_support(indices=True)
    selected_df = X.iloc[:,selected_columns_indices]
    selected_columns = selected_df.columns.tolist()
    return selected_columns



## FEATURE SELECTION

def get_most_recurrent(df, portion=0.05, limit=None):
    if limit is None:
        limit = int(portion*len(df.columns))
    most_recurrent_ = df.drop(['label', 'sublabel'], axis=1).sum().sort_values(ascending=False).iloc[:limit]
    return most_recurrent_


def select_k_best(df, select_function=f_classif, k=10, label='label'):
    X = df.drop(['label', 'sublabel'], axis=1)
    y = df[label]
    selector = SelectKBest(select_function, k=k).fit(X, y)
    selected_columns_indices = selector.get_support(indices=True)
    selected_df = X.iloc[:,selected_columns_indices]
    selected_columns = selected_df.columns.tolist()
    return selected_columns


def get_feature_importances(X, y, model=RandomForestClassifier(), limit=None):
    model.fit(X,y)
    fi = model.feature_importances_
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


def save_selected_features(df, k, model=RandomForestClassifier(), path='selected-features', file='untitled.pkl', prefix=None, preview=None):
    X, y = get_X_y(df)
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




