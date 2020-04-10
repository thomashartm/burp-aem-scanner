package biz.netcentric.aem.securitycheck.http;

public interface ResponseEntity {

    String getMessageBody();

    byte[] getRawResponse();

    int getStatusCode();

    String getMimeType();

    java.util.List<String> getHeaders();

    java.util.List<Cookie> getCookies();
}
