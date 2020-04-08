package biz.netcentric.aem.securitycheck.engine;

import biz.netcentric.aem.securitycheck.EnvironmentContext;
import biz.netcentric.aem.securitycheck.HttpClientProvider;
import biz.netcentric.aem.securitycheck.model.SecurityCheck;
import biz.netcentric.aem.securitycheck.model.SecurityCheckRequest;
import biz.netcentric.aem.securitycheck.util.Logger;
import biz.netcentric.aem.securitycheck.http.RequestDelegate;
import burp.http.ResponseEntity;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.concurrent.Callable;

public class SecurityCheckCallable implements Callable<CheckResult> {

    private final SecurityCheck securityCheck;

    private final Logger logger;

    private final HttpClientProvider httpClientProvider;


    public SecurityCheckCallable(SecurityCheck securityCheck, EnvironmentContext context) {
        this.securityCheck = securityCheck;
        this.logger = context.getLogger();
        this.httpClientProvider = context.getHttpClientProvider();
    }

    @Override
    public CheckResult call() throws Exception {
        logger.log("Callable: " +  securityCheck.getId());
        List<SecurityCheckRequest> requestSteps = securityCheck.getRequestSteps();

        requestSteps.forEach(requestStep ->{
            scan(requestStep);
        });

        return new CheckResult();
    }

    public void scan(SecurityCheckRequest step){
        final List<String> pathMutations = step.createPathMutations();

        for(final String pathMutation : pathMutations) {

            try {
                final URL url = this.httpClientProvider.createUrl(pathMutation);
                final RequestDelegate requestDelegate = this.httpClientProvider.createRequestDelegate(step.getMethod());
                ResponseEntity entity = requestDelegate.send(url);
                logger.log(pathMutation +  " returns status Code " + entity.getStatus());
            } catch (MalformedURLException e) {
                this.logger.error(e, "Unable to create URL to " +  pathMutation);
            }


        }

    }

    public void report(){

    }
}
