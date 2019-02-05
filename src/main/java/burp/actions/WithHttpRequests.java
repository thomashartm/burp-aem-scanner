package burp.actions;

import burp.BurpHelperDto;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IResponseInfo;

import java.net.URL;
import java.util.Arrays;

/**
 * Adds support for sending http requests.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public interface WithHttpRequests {

    /**
     * Sends a request
     *
     * @param url         Url
     * @param httpService http service
     * @return IHttpRequestResponse
     */
    default IHttpRequestResponse sendRequest(final URL url, final IHttpService httpService) {
        final byte[] request = getHelperDto().getHelpers().buildHttpRequest(url);
        return getHelperDto().getCallbacks().makeHttpRequest(httpService, request);
    }

    /**
     * Transforms a response to a String representation
     *
     * @param requestResponse
     * @return
     */
    default String responseToString(final IHttpRequestResponse requestResponse) {
        final byte[] response = requestResponse.getResponse();
        final IResponseInfo responseInfo = this.getHelperDto().getHelpers().analyzeResponse(response);
        final byte[] body = Arrays.copyOfRange(response, responseInfo.getBodyOffset(), response.length);

        return this.getHelperDto().getHelpers().bytesToString(body);
    }

    BurpHelperDto getHelperDto();
}
