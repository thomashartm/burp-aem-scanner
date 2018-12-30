# AEM Security Scanner

AEM is an enterprise grade content management system used by a variety of high profile companies. 
AEM is a powerful but complex system and requires thoughtful handling of defaults and configurations. 
Therefore it leaves room for plenty of security bugs.

The AEM Security Scanner is a burp extension providing  support for a number of Adobe's security checklist verifications 
and evaluates typical AEM and Dispatcher misconfigurations. 

# How to build
Execute the maven build in the root of the package.
` mvn clean install`

To debug the extension, open burp via commandline with remote debugging enabled. 
`java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005 -jar burpsuite_pro.jar`

# How to install 
Open Burp extender and the compiled and assembled JAR extensions.
The extender will automatically register all scans and the scanner will run in the context of passive and active auditing.
