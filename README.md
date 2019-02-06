# Burp AEM Security Scanner Extension
[![Build Status](https://travis-ci.org/thomashartm/burp-aem-scanner.svg?branch=master)](https://travis-ci.org/thomashartm/burp-aem-scanner)

AEM is an enterprise grade content management system used by a variety of high profile companies. 
AEM is a powerful but complex system and requires thoughtful handling of defaults and configurations. 
Therefore it leaves room for plenty of security bugs.

The Burp AEM Security Scanner is a burp extension providing support for a number of Adobe's security checklist verifications 
and evaluates typical AEM and Dispatcher misconfigurations. 

## Burp Version
The extension uses is triggered through a context menu extension and therefore does not require the active scanner.

# How to use
Select one or multiple pages from within the Target sitemap. Then click on the relevant security check categories whoch you are planning to execute.

![AEM Actions Menu](https://github.com/thomashartm/burp-aem-scanner/blob/master/docs/aem-sec-check.jpg "AEM Actions")

The security checks will be executed by a thread pool in the background to check progress, please look into the extender output.

# How to build
Execute the maven build in the root of the package.

` mvn clean package`

The compiled and deployable artifact is located in the target directory.

To debug the extension, open burp via commandline with remote debugging enabled. 

`java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005 -jar burpsuite_pro.jar`

# How to install 
Build the project.
Then open Burp extender and select the compiled and assembled JAR.
The extender will automatically register all scans and the scanner will run in the context of passive and active auditing.
