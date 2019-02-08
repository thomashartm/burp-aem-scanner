# Burp AEM Scanner
Burp AEM Scanner is an AEM focussed plugin which supports the evaluation of well known misconfigurations of AEM installations.

# How to build
The extension is written in java. Please use maven >= 3.3.9 to build it.


`mvn clean install`


The compiled and packaged jar is located inside target folder.
 
# How to install 
Open the Extender tab and add the extension jar

# Contributions
If you have suggestions and ideas for improvement feel free to contact me or just raise a pull request. I'm happy to discuss it.

# Credits
It is based on Adobe's AEM/Dispatcher security checklist and implements the checks discovered and highlighted by Mikhail Egorov <0ang3el@gmail.com> https://github.com/0ang3el/aem-hacker/blob/master/aem_hacker.py

