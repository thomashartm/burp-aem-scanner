package biz.netcentric.aem.securitycheck.engine;

import biz.netcentric.aem.securitycheck.http.Detector;
import biz.netcentric.aem.securitycheck.model.SecurityCheck;

import java.util.concurrent.Callable;

public class SecurityCheckCallable implements Callable<CheckResult> {

    private final SecurityCheck securityCheck;

    private final Detector detector;

    public SecurityCheckCallable(SecurityCheck securityCheck, Detector detector) {
        this.detector = detector;
        this.securityCheck = securityCheck;
    }

    @Override
    public CheckResult call() throws Exception {
        System.out.println(securityCheck.getId());
        return new CheckResult();
    }
}
