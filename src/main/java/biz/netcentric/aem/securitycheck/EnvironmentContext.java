package biz.netcentric.aem.securitycheck;

import biz.netcentric.aem.securitycheck.util.Logger;

import java.net.URL;

public interface EnvironmentContext {

    Logger getLogger();

    HttpClientProvider getHttpClientProvider();
}
