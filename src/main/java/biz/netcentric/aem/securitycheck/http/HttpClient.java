package biz.netcentric.aem.securitycheck.http;

import biz.netcentric.aem.securitycheck.model.HttpMethod;
import burp.http.RequestDelegate;

public interface HttpClient {

    /**
     * Provides the request method for a specfic http method
     * @param method
     * @return
     */
    RequestDelegate create(HttpMethod method);
}
