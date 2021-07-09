# ransomware-preencryption-detector
Safe browsing facility that detects ransomware in the pre-encryption execution step without imposing any danger to host instance.

# Introduction

In 2020 only, ransomware “business” brought $20 Billion to cyber criminals. This appalling figure is rising gradually every year and existing solutions are not able to combat this threat. According to Cybercrime Magazine this figure, assuming current trend, can rise up and exceed $265 Billion By 2031. (https://cybersecurityventures.com/global-ransomware-damage-costs-predicted-to-reach-250-billion-usd-by-2031/)

What’s the reason behind ransomware’s success? Nowadays antivirus software do not differ much from their first prototypes. They operate based on a library of signatures (hashes) of known malware that they gather due to research, honeypots or more and more thanks to VirusTotal online tool. But what if malware or, particularly, ransomware sample is not known to a given Antivirus? – Then Antivirus will not stop malicious program from damaging computer, because its signature does not exist in the library.

Instead of relying on every samples’ signature, we propose using Windows System API calls and other system information to detect malicious behavior and protect end user from downloading and running malware/ransomware.
*Data gathering*

Prior to getting data to analyze and work with we had to find goodware, malware and ransomware samples. To find the latter we have used all possible options, starting with Google and GitHub and up to Darknet hacking websites. In total, we have gathered X goodware, X malware and X ransomware samples.

Eventually, we have produced reports dataset thanks to Cuckoo Sandbox (https://cuckoosandbox.org). This sandbox software provides detailed and valuable insights on internal processes running in OS during file execution.

# Structure of raw data

Reports follow json file structure. It can be described as follows:
Main file structure :

{   "info": 	{ },
    "signatures": [  { }, { }, …  ],
    “target”:	{ },
    “dropped”:	[ ],
    "behavior": 	{ "generic": 	[ ],
   "apistats": 	{ },
   "processes": 	[ { “calls”: [ {},{},.. ] }, ... ],
		   "processtree": [ {}, {} .. ],
		   "summary": 	{ "files": [ ],
			             	  "keys": [ ],
			                "dll_loaded": [ ],
                                                            "mutexes": [ ],
			                "resolves_host": [ ],
				  … }
		}
   “static”: 	{ "pe_imports": [ ],
   "pe_exports": [ ],
   "pe_timestamp": "",
   "imported_dll_count": “”,
   "pe_sections": [ ],
   …,
},
   "network": 	{ "http" : [ ],
   "tcp" : [ ],
   "udp" : [ ],
   "dns" : [ ],
   "hosts" : [ ],
},     
   "debug": 	{ "log": [ ]
   "cuckoo" : [ ] 
},
  “screenshots”: [ ],
  “strings” : 	[ ],
  “metadata”:	{ },
}

After deep analysis of data that’s we acquired with Cuckoo, taking into account that it can vary from one case to another, we agreed on extracting specific values that we will describe later in the article.

![cuckoo-reports-parser-pipeline](https://user-images.githubusercontent.com/54726923/122111097-9c81ea80-ce1f-11eb-9a6f-6ee5627d5716.jpg)

We have used custom JSON parser to retrieve needed data from reports. It’s implementation, using the report json structure, orjson library and multiprocessing, extracting data from 1000 json reports, totaling 20 gigabytes in size took only 125 seconds. 
(one file was 1.1 gigabyte in size and took 39 seconds to process)


# Key features

Indicators of compromise (IOCs) are “pieces of forensic data, such as data found in system log entries or files, that identify potentially malicious activity on a system or network.” Indicators of compromise aid information security and IT professionals in detecting data breaches, malware infections, or other threat activity. By monitoring for indicators of compromise, organizations can detect attacks and act quickly to prevent breaches from occurring or limit damages by stopping attacks in earlier stages.

1.	API Calls 
System call provides the services of the operating system to the user programs via Application Program Interface(API). It provides an interface between a process and operating system to allow user-level processes to request services of the operating system. System calls are the only entry points into the kernel system.

2.	DLL
Stands for "Dynamic Link Library." A DLL (. dll) file contains a library of functions and other information that can be accessed by a Windows program. When a program is launched, links to the necessary . Some DLLs come with the Windows operating system while others are added when new programs are installed.

3.	File Operations
A file is an abstract data type. To define a file properly, we need to consider the operations that can be performed on files. 
Six basic file operations. The OS can provide system calls to create, write, read, reposition, delete, and truncate files.

4.	Registry key operations
Registry keys are container objects similar to folders. Registry values are non-container objects similar to files. Keys may contain values and subkeys. Keys are referenced with a syntax similar to Windows' path names, using backslashes to indicate levels of hierarchy.
- Why using this data?
A tactic that has been growing increasingly common is the use of registry keys to store and hide next step code for malware after it has been dropped on a system.

5.	PE Imports
 PE or Portable Executable is the Windows executable file format. Studying the PE format helps us understand how windows internals function which in turn makes us better programmers. It is even more important for reverse engineers who want to figure out the intricate details of often obfuscated binaries.
Whenever you execute a file, the windows loader would first load the PE file from disk and map it into memory. The memory map of the PE file is called a module. It is important to note that the loader may not just copy the entire contents from disk to memory. Instead, the loader looks at the various values in the header to find different parts of the PE in the file and then maps parts of it to memory.
(http://ulsrl.org/pe-portable-executable/ )

6.	Prevalence and impact of low-entropy packing schemes in the malware ecosystem
One common technique adversaries leverage is packing binaries. Packing an executable is similar to applying compression or encryption and can inhibit the ability of some technologies to detect the packed malware. High entropy is traditionally a tell-tale sign of the presence of a packer, but many malware analysts may have probably encountered low-entropy packers more than once. Numerous popular tools (e.g., PEiD, Manalyze, Detect It Easy), malware-related courses, and even reference books on the topic, affirm that packed malware often shows a high entropy. As a consequence, many researchers use this heuristic in their analysis routines. It is also well known that the tools typically used to detect packers are based on signature matching and may sometimes combine other heuristics, but again, the results are not completely faithful, as many of the signatures that circulate are prone to false positives.
Cisco Talos Intelligence Group - Comprehensive Threat Intelligence: New Research Paper: Prevalence and impact of low-entropy packing schemes in the malware ecosystem


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
We have used AWS for our architecture as it has many benefits in comparison to classic server-oriented one, including ease of scalability, computational power in-demand, variety of built-in tools.
The main components are:

![Screenshot 2021-06-15 at 12 22 58](https://user-images.githubusercontent.com/42537931/122037594-01fcb980-cdd5-11eb-990f-92f7e314acd8.png)

![Screenshot 2021-06-15 at 12 24 42](https://user-images.githubusercontent.com/42537931/122037424-daa5ec80-cdd4-11eb-9987-32ebb6ddc658.png)

![Screenshot 2021-06-15 at 12 24 50](https://user-images.githubusercontent.com/42537931/122037450-e1ccfa80-cdd4-11eb-80e2-abe02196beb7.png)



# Some challenges we overcame
One of the big challenges in this project is dealing with Cuckoo analysis json reports. On one hand, their size can reach up to 500-700 megabytes, which requires us to figure out a memory efficient and fast way to load and process them. On the other hand, understanding the extensive nested structure of the reports and interpreting the meaning of each section poses a challengeas well and may require the help of an operating systems expert. In fact, Cuckoo provides very detailed reports outlining the behavior of the file when executed inside a realistic isolated environment, and due to this detailed nature and the adaptive structure of the reports to eachsubmitted file for analysis, cuckoo doesn’t have enough documentation of the reports’ contents on their official website.
Since data is mainly categorical with more than 1000 possible features that reflect the file’s behavior in a Windows environment, the challenge would be to successfully identify the important features that can differentiate between ransomware and goodware. This requires usto properly study features’ importance and implement different variable selection algorithms. We’ll also deal with the potential problem of variables’ multicollinearity and explore various dimensionality reduction methods. An important question in this eventuality would be the relevance of feature elimination when the categorical variables belong to a bigger category.
Another challenge in dealing with multi-class categorical variables is when the training dataset doesn’t provide an exhaustive list of all possible classes. When deployed, the model would most probably be faced with unseen classes. For example, there are over 1000 possible Windows API calls and the collected dataset so far only contains about 250 of them. Dealing with this issue will require us to explore multiple strategies for handling unseen classes to achieve the best performance. An additional option would be model retraining in production with new data via incremental learning techniques.

## Stack
* Python,
* Pandas, SkLearn, TensorFlow, Keras, Numpy, MatplotLib
* Selenium, Beautiful Soup,
* AWS,
* BOTO3

