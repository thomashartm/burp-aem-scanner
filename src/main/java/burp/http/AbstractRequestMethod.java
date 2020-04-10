package burp.http;

import biz.netcentric.aem.securitycheck.http.Cookie;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public abstract class AbstractRequestMethod {

    private String responseBodyToString(final IResponseInfo responseInfo, byte[] rawResponse) {
        final byte[] body = Arrays.copyOfRange(rawResponse, responseInfo.getBodyOffset(), rawResponse.length);
        return this.getExtenderCallback().getHelpers().bytesToString(body);
    }

    private String statedMimeType(final IHttpRequestResponse requestResponse){
        final IResponseInfo responseInfo = toResponseInfo(requestResponse);
        return responseInfo.getStatedMimeType();
    }

    private  IResponseInfo toResponseInfo(final IHttpRequestResponse requestResponse){
        return getExtenderCallback().getHelpers().analyzeResponse(requestResponse.getResponse());
    }

    public BurpResponse createResponse(final IHttpRequestResponse requestResponse){
        final byte[] rawResponse = requestResponse.getResponse();
        final IResponseInfo responseInfo = toResponseInfo(requestResponse);

        final List<Cookie> cookies = responseInfo.getCookies()
                .stream()
                .map(cookie -> new BurpCookie(cookie))
                .collect(Collectors.toList());

        return BurpResponse.builder()
                .rawResponse(rawResponse)
                .messageBody(responseBodyToString(responseInfo, rawResponse))
                .statusCode(responseInfo.getStatusCode())
                .headers(responseInfo.getHeaders())
                .cookies(cookies)
                .mimeType(responseInfo.getStatedMimeType())
                .build();
    }

    protected abstract IBurpExtenderCallbacks getExtenderCallback();

}
