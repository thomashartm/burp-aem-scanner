package biz.netcentric.aem.securitycheck.http;

import java.util.Date;

public interface Cookie {

    String domain();

    String path();

    String value();

    String name();

    Date expirationTime();
}
