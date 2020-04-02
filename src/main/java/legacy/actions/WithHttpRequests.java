package legacy.actions;

import legacy.BurpHelperDto;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IResponseInfo;

import java.net.MalformedURLException;
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
    IHttpRequestResponse sendRequest(final URL url, final IHttpService httpService) throws MalformedURLException;

    /**
     * Transforms a response to a String representation
     *
     * @param requestResponse
     * @return
     */
    default String responseBodyToString(final IHttpRequestResponse requestResponse) {
        final byte[] response = requestResponse.getResponse();
        final IResponseInfo responseInfo = this.getHelperDto().getHelpers().analyzeResponse(response);
        final byte[] body = Arrays.copyOfRange(response, responseInfo.getBodyOffset(), response.length);

        return this.getHelperDto().getHelpers().bytesToString(body);
    }

    BurpHelperDto getHelperDto();
}
