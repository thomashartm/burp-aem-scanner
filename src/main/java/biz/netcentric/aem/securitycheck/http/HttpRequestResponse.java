package biz.netcentric.aem.securitycheck.http;

import java.net.URL;
import java.util.Map;

public interface HttpRequestResponse {

    URL getRequestUrl();

    int getStatusCode();

    boolean bodyContains(final String token);

    Map<String, String> getResponseHeaders();

    byte[] getRawRequest();

    byte[] getRawResponse();
}
