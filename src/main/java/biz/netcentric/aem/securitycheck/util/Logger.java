package biz.netcentric.aem.securitycheck.util;

public interface Logger {

    void log(String message);

    void log(String pattern, String... messages);

    void log(Exception ex);

    void log(Exception ex, String message);

    void error(String message);

    void error(String pattern, String... messages);

    void error(Exception ex);

    void error(Exception ex, String message);
}
