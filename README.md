# Burp AEM Security Scanner Extension
[![Build Status](https://travis-ci.org/thomashartm/burp-aem-scanner.svg?branch=master)](https://travis-ci.org/thomashartm/burp-aem-scanner)

Burp AEM Security Scanner is an AEM focussed plugin which supports the evaluation of well known misconfigurations of AEM installations.
It supports the verification of a number of Adobe's security checklist topics and evaluates typical AEM and Dispatcher misconfigurations. 


### What is AEM
AEM is an enterprise grade content management system used by a variety of high profile companies. 
AEM is a powerful but complex system and requires thoughtful handling of defaults and configurations. 
Therefore it leaves room for plenty of security bugs.

## Installation Requirements
Burp Community is sufficient as the extension does not require the active or passive scanner.

# How to use
Select one or multiple pages from within the Target sitemap. Then click on the relevant security check categories which you are planning to execute.

The scanner extension will use the selected URLs and pass them to the checks. 
Each check is self contained and will decide what to use from the provided URL, e.g. just the host and port e.g. to use it as a base to build the CRX or Felix Console URLs and to test dispatcher bypasses for them or the complete URL e.g. to verify if the particular page is vulnerable for enumeration.

![AEM Actions Menu](https://github.com/thomashartm/burp-aem-scanner/blob/gh-pages/images/aem-actions.jpg "AEM Actions")

The security checks will be executed by a thread pool in the background to check progress, please look into the extender output.

# Why doesn't it use active scanner?
First of all because I want to make the checks available for everyone. 
Additionally and that is personally my major concern, the Burp extender API does not allow to trigger "one execution per host" checks e.g. to test for the existence of CRX and other resources, with the result of many unnecessary requests.
Therefore I decided to manually trigger those scans.

# How to build and develop
The extension is written in java. Please use maven >= 3.3.9 to build it. 
Execute the maven build in the root of the package.

` mvn clean package`

The compiled and deployable artifact is located in the target directory.
To debug the extension, open burp via commandline with remote debugging enabled. 

`java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005 -jar burpsuite_pro.jar`

# How to install 
Build the project.
Then open Burp extender and select the compiled and assembled JAR.
The extender will automatically register the scanner menu including all actions.
Click a specific action to activate the detection for the provided URL.

Only the selected URLs will be used as a base for the respective scan.

# Contributions
If you have suggestions and ideas for improvement feel free to contact me or just raise a pull request. I'm happy to discuss it.

# Credits
It is based on Adobe's AEM/Dispatcher security checklist and implements many of the checks discovered and highlighted by Mikhail Egorov <0ang3el@gmail.com> https://github.com/0ang3el/aem-hacker/blob/master/aem_hacker.py

