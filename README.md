# Burp AEM Security Scanner
[![Build Status](https://travis-ci.org/thomashartm/burp-aem-scanner.svg?branch=master)](https://travis-ci.org/thomashartm/burp-aem-scanner)

AEM is an enterprise grade content management system used by a variety of high profile companies. 
AEM is a powerful but complex system and requires thoughtful handling of defaults and configurations. 
Therefore it leaves room for plenty of security bugs.

The Burp AEM Security Scanner is a burp extension providing support for a number of Adobe's security checklist verifications 
and evaluates typical AEM and Dispatcher misconfigurations. 

## Burp Version
The extension uses the active scanning capabilities and therefore requires Burp Pro

## Supported Features

The burp extension currently supports the following features:

| Check  | Type  |  Description |
|---|---|---|
|AEM Fingerprint|passive| Checks if any page exposes information which clearly identifies the system as Adobe AEM |
|Content Grapping Check|active| Verifies if the dispatcher configuration is vulnerable to information leakage and exposes critical information |
|Dispatcher Security Check|active| Checks if administrative or dangerous features are exposed to the ouside world |

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
