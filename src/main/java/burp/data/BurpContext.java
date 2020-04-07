package burp.data;

import biz.netcentric.aem.securitycheck.EnvironmentContext;
import biz.netcentric.aem.securitycheck.HttpClientProvider;
import biz.netcentric.aem.securitycheck.util.Logger;
import lombok.Builder;

import java.net.URL;

@Builder
public class BurpContext implements EnvironmentContext {

    private Logger logger;

    private HttpClientProvider clientProvider;


    @Override
    public Logger getLogger() {
        return this.logger;
    }

    @Override
    public HttpClientProvider getHttpClientProvider() {
        return this.clientProvider;
    }

}
