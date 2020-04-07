package biz.netcentric.aem.securitycheck.http;

import biz.netcentric.aem.securitycheck.HttpClientProvider;

public class Detector {

    HttpClientProvider httpClientProviderDelegate;

    public Detector(HttpClientProvider httpClientProviderDelegate) {
        this.httpClientProviderDelegate = httpClientProviderDelegate;
    }

    public void scan(){

    }

    public void report(){

    }
}
