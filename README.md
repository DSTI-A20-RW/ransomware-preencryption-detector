# ransomware-preencryption-detector

## Project Objective
Create a web application to detect ransomware pre-encryption without imposing any danger to host computer.

## Why it matters?
In 2020 only, ransomware “business” brought $20 Billion to cyber criminals. This appalling figure is rising gradually every year and existing solutions are not able to combat this threat.

## How do classic Antivirus programs work nowadays?
Nowadays antivirus programs do not differ much from their first prototypes. They operate based on a library of signatures (hashes) of known malware that they gather due to research, honeypots or more and more thanks to VirusTotal online tool. But what if malware or, particularly, ransomware sample is not known to a given Antivirus? 
– Then Antivirus will not stop malicious program from damaging computer, because its signature does not exist in the library.

## What we suggest?
Instead of relying on every samples’ signature, we propose using Windows System API calls and other system information to detect malicious behavior and protect end user from 
downloading and running malware/ransomware.

## How are we going to make it work?
Primarily to gather data we have used Cuckoo Sandbox that produces reports after running given program sample. These reports are being treated with Python Parser to get necessary data from Cuckoo .json reports: as per now we use API calls, DLL, Windows registry keys, Imports, duration of execution and other antiviruses results. The data used is subject to change.

For data gathering we are using scrapper to harvest existing reports. We have also found pre-generated dataset with cuckoo reports for goodware and malware. We do also generate our own reports by running ransomware samples gathered online. It allows us to label data precisely as ransomware is part of a bigger group called malware. 

All reports are being parsed and multi-processed to generate different .csv datasets that we read with pandas. Categorical data prevails in the data set, it is currently challenging, we use one-hot encoding and summary data.

## Some challenges 
One of the big challenges in this project is dealing with Cuckoo analysis json reports. On one hand, their size can reach up to 500-700 megabytes, which requires us to figure out a memory efficient and fast way to load and process them. On the other hand, understanding the extensive nested structure of the reports and interpreting the meaning of each section poses a challengeas well and may require the help of an operating systems expert. In fact, Cuckoo provides very detailed reports outlining the behavior of the file when executed inside a realistic isolated environment, and due to this detailed nature and the adaptive structure of the reports to eachsubmitted file for analysis, cuckoo doesn’t have enough documentation of the reports’ contents on their official website. 

Since data is mainly categorical with more than 1000 possible features that reflect the file’s behavior in a Windows environment, the challenge would be to successfully identify the important features that can differentiate between ransomware and goodware. This requires usto properly study features’ importance and implement different variable selection algorithms. We’ll also deal with the potential problem of variables’ multicollinearity and explore various dimensionality reduction methods. An important question in this eventuality would be the relevance of feature elimination when the categorical variables belong to a bigger category.

Another challenge in dealing with multi-class categorical variables is when the training dataset doesn’t provide an exhaustive list of all possible classes. When deployed, the model would most probably be faced with unseen classes. For example, there are over 1000 possible Windows API calls and the collected dataset so far only contains about 250 of them. Dealing with this issue will require us to explore multiple strategies for handling unseen classes to achieve the best performance. An additional option would be model retraining in production with new data via incremental learning techniques.

## Machine Learning models to consider
* Random forests and other variations
* Artificial Neural Network
* Naïve Bayes
* K-nearest neighbors
* Gradient Boosting: XGBoost, AdaBoost, LightGBM, CatBoost
* SVM
* Stacking/Blending models
* LSTM (sequential data)

On top of classification algorithms, as there’s a severe shortage of available ransomware samples online, we will have to deal with imbalanced classification using techniques such as SMOTE (Synthetic Minority Oversampling Technique) as well as bagging and boosting 
techniques for imbalanced data.

We also intend to try clustering algorithms to check whether we can identify clusters of malware types, other than ransomware, such as : Worms, Trojans, Spyware, RATs, Stealers, Bankers etc.

## Preliminary Architecture
The main components are:

![Screenshot 2021-06-15 at 12 22 58](https://user-images.githubusercontent.com/42537931/122037594-01fcb980-cdd5-11eb-990f-92f7e314acd8.png)

![Screenshot 2021-06-15 at 12 24 42](https://user-images.githubusercontent.com/42537931/122037424-daa5ec80-cdd4-11eb-9987-32ebb6ddc658.png)

![Screenshot 2021-06-15 at 12 24 50](https://user-images.githubusercontent.com/42537931/122037450-e1ccfa80-cdd4-11eb-80e2-abe02196beb7.png)


## Stack
* Python,
* Pandas, SkLearn, TensorFlow, Keras, Numpy, MatplotLib
* Selenium, Beautiful Soup,
* AWS,
* BOTO3

