# Asgardio OIDC SDK for Java

[![Build Status](https://img.shields.io/jenkins/build?jobUrl=https%3A%2F%2Fwso2.org%2Fjenkins%2Fjob%2Fasgardio%2Fjob%2Fasgardio-java-oidc-sdk%2F&style=flat)](https://wso2.org/jenkins/job/asgardio/job/asgardio-java-oidc-sdk/)
[![Stackoverflow](https://img.shields.io/badge/Ask%20for%20help%20on-Stackoverflow-orange)](https://stackoverflow.com/questions/tagged/wso2is)
[![Join the chat at https://join.slack.com/t/wso2is/shared_invite/enQtNzk0MTI1OTg5NjM1LTllODZiMTYzMmY0YzljYjdhZGExZWVkZDUxOWVjZDJkZGIzNTE1NDllYWFhM2MyOGFjMDlkYzJjODJhOWQ4YjE](https://img.shields.io/badge/Join%20us%20on-Slack-%23e01563.svg)](https://join.slack.com/t/wso2is/shared_invite/enQtNzk0MTI1OTg5NjM1LTllODZiMTYzMmY0YzljYjdhZGExZWVkZDUxOWVjZDJkZGIzNTE1NDllYWFhM2MyOGFjMDlkYzJjODJhOWQ4YjE)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/wso2/product-is/blob/master/LICENSE)
[![Twitter](https://img.shields.io/twitter/follow/wso2.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=wso2)
---

The Asgardio OIDC SDK for Java enables software developers to integrate OIDC based SSO authentication with Java Web
applications. The SDK is built on top of the NimbusDS OAuth 2.0 SDK with OpenID Connection extensions library which
 allows Java developers to develop cross-domain single sign-on and federated access control solutions with minimum
  hassle.

## Getting Started

You can experience the end-to-end capabilities of Asgardio Java OIDC SDK by trying out the sample application
 featured in Asgardio OIDC tomcat agent getting started guide [TODO link].

In this section, we would be looking at how you can embed the Asgardio Java OIDC SDK to your existing Java web app.

### Table of Contents
- [Initializing the SDK](#initializing-the-sdk)
  * [Maven dependency](#maven-dependency)
  * [Configuration file](#adding-the-configuration-properties)
  * [OIDC Manager](#oidc-manager)
- [Login](#login)
- [Handle Callback response](#handle-callback-response)
- [Logout](#logout)
- [Request Resolving](#request-resolving)

### Initializing the SDK
This section covers the preliminary steps needed for getting the SDK ready to be used in your java webapp.

#### Maven dependency
You can add the Asgardio Java OIDC SDK to your java project by installing it as a maven dependency:

```xml
<dependency>
    <groupId>io.asgardio.java.oidc.sdk</groupId>
    <artifactId>io.asgardio.java.oidc.sdk</artifactId>
    <version>0.1.2</version>
</dependency>
```
#### Adding the configuration properties
You need to add the configuration properties which provides the set of required parameters specific to the OIDC flows as
 described by the OIDC Agent configuration catalog [link to configuration catalog]. For a sample configuration
  properties file, please refer to the one provided with the sample application in Asgardio OIDC Tomcat Agent [link].
  
  You can use the default `FileBasedOIDCConfigProvider` for using file-based configurations. Or else, you have the
   freedom to implement your own custom configuration provider by implementing the interface, `OIDCConfigProvider`.
   
   For using the default `FileBasedOIDCConfigProvider`, you can use the following snippet.
   
   // public FileBasedOIDCConfigProvider(InputStream fileInputStream)
   
   ```java
	    File configFile = new File("path/to/config/file");
	    InputStream configStream = new FileInputStream(configFile);
        OIDCConfigProvider configProvider = new FileBasedOIDCConfigProvider(configStream);
```
Now, the next step would be to create an `OIDCManager` instance which would provide you with the basic actions you
 want to perform in securing your Java webapp with OpenID Connect.

#### OIDC Manager

The OIDCManager interface provides a set of APIs which you can use to initiate a login flow, initiate a logout flow
, and handle the callback responses from the OpenID Provider. For using these APIs, you only would need a single
 instance of a `OIDCManager` implementation. By default, Asgardio Java OIDC SDK provides the `DefaultOIDCManger
 ` which is an implementation of the OIDCManager interface.
  
  For users who opt to use HTTP-session-based storage, the SDK provides an HTTP-session-based wrapper out of the box
   which adds HTTP session specific storing mechanisms on top of the `DefaultOIDCManager`.
   
   If you opt to use a different session storing system, you have the flexibility to write your own implementation of
    the `OIDCManager` interface and integrate it with your webapp.
    For this tutorial, we will be using the `HTTPSessionBasedOIDCProcessor` which is provided out of the box.
    The constructor for the `HTTPSessionBasedOIDCProcessor` takes in `OIDCAgentConfig` type object.
    
    public HTTPSessionBasedOIDCProcessor(OIDCAgentConfig oidcAgentConfig);

   This can be obtained by the OIDCConfigProvider instance we created earlier. Add the following code snippet to
    create the `HTTPSessionBasedOIDCProcessor` instance.
    
    OIDCAgentConfig config = configProvider.getOidcAgentConfig();
    HTTPSessionBasedOIDCProcessor oidcManager = new HTTPSessionBasedOIDCProcessor(config);
    
  After creating one instance at the start, you can re-use the instance for sending every request and handling the
   responses.
   The `HTTPSessionBasedOIDCProcessor` provides you with the following APIs which can be used to initiate requests
    and handle responses.
    
1. `sendForLogin(HttpServletRequest request, HttpServletResponse response)`

2. `handleOIDCCallback(HttpServletRequest request, HttpServletResponse response)`

3. `logout(HttpServletRequest request, HttpServletResponse response)`
  
  In the following sections, we would look into these APIs in detail with the possible scenarios which these can be
   used.

### Login
 ```java
    oidcmanager.sendForLogin(request, response);
 ```
  
The following are the parameters to the API.
  
_request_ : Incoming `HttpServletRequest`.

_response_ : Outgoing `HttpServletResponse`.

This method can be used to send the user for authentication. The API would build an authentication request and
 redirect the user for authentication. Relevant information regarding the authentication session would be written to
  the http session.
 

### Handle Callback Response

 ```java
    oidcManager.handleOIDCCallback(request, response);
 ```
  
The following are the parameters to the API.
  
_request_: Incoming `HttpServletRequest`.

_response_ : Outgoing `HttpServletResponse`.
 
 This method should be used to process the OIDC callback response. It would obtain access tokens and refresh
  tokens, validate the ID token issued by the OpenID Provider, and redirect the user to secured pages.

### Logout
   
```java
   oidcManager.logout(request, response);
```
     
   The following are the parameters to the API.
     
_request_ : Incoming `HttpServletRequest`.

_response_ : Outgoing `HttpServletResponse`.
   
This method can be used to logout the user from the session. The API would build a logout request and
 log out the user from the authenticated session at the OpenID Provider.
 
 ### Request Resolving
 
 Asgardio Java OIDC SDK provides utils to process the incoming HTTP requests and resolve them to be certain types
 . You can determine whether a request is a callback response, a logout request, an error request, etc. by using the
  provided `OIDCRequestResover` in places where the webapp is intercepting HTTP requests.
  
  You can create a `OIDCRequestResolver` instance with the following snippet.
  
  ```java
    OIDCRequestResolver requestResolver = new OIDCRequestResolver(request, oidcAgentConfig);
```
The following are the parameters.

_oidcAgentConfig_ : `OIDCAgentConfig` object which can be obtained through the `OIDCConfigProvider` implementation as
 previously shown.

_response_ : Outgoing `HttpServletResponse`.

  The provided util methods are as follows:
  
  | Method                      | Description                 | Returns        |
  | -------------               |-------------                | ------------   |
  |isCallbackResponse()|Checks if the request is a callback response. | boolean |
  |isLogoutURL()|Checks if the request is a logout request. | boolean |
  |isSkipURI()|Checks if the request is a URI to skip. | boolean |
  |isAuthorizationCodeResponse()|Checks if the request is an Authorization Code response. | boolean |
  
 
### Github
The SDK is hosted on github. You can download it from:
- Latest release: https://github.com/asgardio/asgardio-java-oidc-sdk/releases/latest
- Master repo: https://github.com/asgardio/asgardio-java-oidc-sdk/tree/master/

### Building from the source

If you want to build **asgardio-java-oidc-sdk** from the source code:

1. Install Java 8
2. Install Apache Maven 3.x.x (https://maven.apache.org/download.cgi#)
3. Get a clone or download the source from this repository (https://github.com/asgardio/asgardio-java-oidc-sdk.git)
4. Run the Maven command ``mvn clean install`` from the ``asgardio-java-oidc-sdk`` directory.

## Contributing

Please read [Contributing to the Code Base](http://wso2.github.io/) for details on our code of conduct, and the
 process for submitting pull requests to us.
 
### Reporting Issues
We encourage you to report issues, improvements, and feature requests creating [git Issues](https://github.com/wso2-extensions/identity-samples-dotnet/issues).

Important: And please be advised that security issues must be reported to security@wso2.com, not as GitHub issues, 
in order to reach the proper audience. We strongly advise following the WSO2 Security Vulnerability Reporting Guidelines
 when reporting the security issues.

## Versioning

For the versions available, see the [tags on this repository](https://github.com/asgardio/asgardio-java-oidc-sdk/tags). 

## License

This project is licensed under the Apache License 2.0 under which WSO2 Carbon is distributed. See the [LICENSE
](LICENSE) file for details.

