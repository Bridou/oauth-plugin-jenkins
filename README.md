Jenkins Bitbucket OAuth Plugin Adaptation
============================

Overview
--------
This Jenkins plugin enables [OAuth](http://oauth.net) authentication.

OAuth Application Security Realm (authentication):
--------------------------------------------

First you need to get consumer key/secret from an OAuth application.

Second, you need to configure your Jenkins.

1. Open Jenkins **Configure System** page.
2. Check **Enable security**.
3. Select **UPM Authentication Plugin** in **Security Realm**.
4. Input your Consumer Key to **Client ID**.
5. Input your Consumer Secret to **Client Secret**.
6. Click **Save** button.

Plugin Build:
--------------------------------------------
* Needed tools:
- apache-maven-3.0.5 
- Java 1.6.0_18

1. Make sure JAVA_HOME points to Java 1.6.0_18 
2. Make sure PATH points to Java 1.6.0_18 binaries and apache-maven-3.0.5 binaries 
3. $ mvn package 
4. $ mvn install

