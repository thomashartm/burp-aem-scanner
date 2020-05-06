package biz.netcentric.aem.securitycheck.http;

import java.util.Date;
import java.util.Map;

public interface Cookie {

    String domain();

    String path();

    String value();

    String name();

    Date expirationTime();

    Map<String, Object> map();
}
