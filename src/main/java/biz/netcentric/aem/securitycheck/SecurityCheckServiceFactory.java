package biz.netcentric.aem.securitycheck;

import biz.netcentric.aem.securitycheck.engine.SecurityCheckServiceImpl;

public class SecurityCheckServiceFactory {

    public static SecurityCheckService createSecurityCheckService(){
        return new SecurityCheckServiceImpl();
    }
}
