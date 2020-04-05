package biz.netcentric.aem.securitycheck.engine;

import biz.netcentric.aem.securitycheck.DslParser;
import biz.netcentric.aem.securitycheck.SecurityCheckService;
import biz.netcentric.aem.securitycheck.http.Detector;
import biz.netcentric.aem.securitycheck.http.HttpClient;
import biz.netcentric.aem.securitycheck.model.SecurityCheck;

import java.util.Arrays;
import java.util.List;

public class SecurityCheckServiceImpl implements SecurityCheckService {

    private static final String[] DEFAULT_BUILD_IN_CHECKS = {"/securitychecks"};

    private final DslParser dslParser;

    private static int THREAD_POOL_SIZE = 5;

    public SecurityCheckServiceImpl() {
        this.dslParser = new DslParser();
    }

    public void runSecurityChecks(final HttpClient httpClient) {
        List<String> checkLocations = getCheckSourceFolder();
        List<SecurityCheck> securityChecks = dslParser.loadScripts(checkLocations);

        SecurityCheckExecutor securityCheckExecutor = null;
        try {
            securityCheckExecutor = new SecurityCheckExecutor(THREAD_POOL_SIZE);

            securityCheckExecutor.init();

            for(SecurityCheck securityCheck : securityChecks){
                Detector detector = new Detector(httpClient);
                SecurityCheckCallable callable = new SecurityCheckCallable(securityCheck, detector);

                securityCheckExecutor.executeAsync(callable);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        } finally {
            if (securityCheckExecutor != null) {
                securityCheckExecutor.stop();
            }
        }
    }


    public List<String> getCheckSourceFolder() {
        return Arrays.asList(DEFAULT_BUILD_IN_CHECKS);
    }

}