package biz.netcentric.aem.securitycheck;

import biz.netcentric.aem.securitycheck.http.HttpClient;
import biz.netcentric.aem.securitycheck.http.Issue;

import java.util.List;

public interface SecurityCheckService {

    void runSecurityChecks(final HttpClient httpClient);
}
