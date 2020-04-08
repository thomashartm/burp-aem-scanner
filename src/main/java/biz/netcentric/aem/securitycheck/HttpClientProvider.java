package biz.netcentric.aem.securitycheck;

import biz.netcentric.aem.securitycheck.model.HttpMethod;
import biz.netcentric.aem.securitycheck.http.RequestDelegate;

import java.net.MalformedURLException;
import java.net.URL;

public interface HttpClientProvider {

    /**
     * Provides the request method for a specific http method delegate
     * @param method
     * @return
     */
    RequestDelegate createRequestDelegate(HttpMethod method);

    URL createUrl(final String path) throws MalformedURLException;
}
