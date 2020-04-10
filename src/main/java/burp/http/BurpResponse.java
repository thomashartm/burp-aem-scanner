package burp.http;

import biz.netcentric.aem.securitycheck.http.Cookie;
import biz.netcentric.aem.securitycheck.http.ResponseEntity;
import lombok.Builder;
import lombok.Getter;

import java.util.List;

/**
 * Provides the results of an HTTP request response execution through a HTTP method such as a GET or a POST to a specific URL.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 04/2020
 */
@Builder
@Getter
public class BurpResponse implements ResponseEntity {

    private String messageBody;

    private byte[] rawResponse;

    private int statusCode;

    private String mimeType;

    private List<String> headers;

    private List<Cookie> cookies;

}
