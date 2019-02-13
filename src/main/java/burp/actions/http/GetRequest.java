package burp.actions.http;

import burp.*;

import java.net.URL;
import java.util.Arrays;
import java.util.List;

/**
 * GET Request abstraction to simplify the generation of customized GET responses with custom request headers.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public class GetRequest implements HttpMethod {

    private final IHttpRequestResponse baseMessage;

    private final IExtensionHelpers helpers;

    private final BurpHelperDto burpHelperDto;

    private final byte[] baseRequest;

    private byte[] message;

    /**
     * {@link java.lang.reflect.Constructor}
     *
     * @param burpHelperDto
     * @param baseMessage
     */
    public GetRequest(BurpHelperDto burpHelperDto, IHttpRequestResponse baseMessage) {
        this.burpHelperDto = burpHelperDto;
        this.helpers = burpHelperDto.getHelpers();
        this.baseMessage = baseMessage;
        this.baseRequest = baseMessage.getRequest();
    }

    public void init(final URL newUrlTarget, final String... additionalHeaders) {
        final byte[] request = this.helpers.buildHttpRequest(newUrlTarget);
        final IRequestInfo requestInfo = this.helpers.analyzeRequest(baseRequest);
        final List<String> headers = requestInfo.getHeaders();

        headers.addAll(Arrays.asList(additionalHeaders));

        this.message = this.helpers.buildHttpMessage(headers, request);
        this.burpHelperDto.getCallbacks().printOutput(helpers.bytesToString(this.message));
    }

    @Override
    public void addRequestParameter(final String name, final String value) {
        if (this.message== null) {
            return;
        }

        final IParameter param = this.helpers.buildParameter(name, value, IParameter.PARAM_URL);
        this.message = this.helpers.addParameter(this.message, param);
    }

    @Override
    public void addBodyParameter(final String name, final String value) {
    }

    public ResponseHolder send() {
        final IHttpRequestResponse requestResponse = this.burpHelperDto.getCallbacks()
                .makeHttpRequest(baseMessage.getHttpService(), this.message);

        return ResponseHolder.create(requestResponse);
    }

    @Override
    public ResponseHolder send(URL url) {
        this.init(url);
        return this.send();
    }

    public static HttpMethod createInstance(final BurpHelperDto burpHelperDto, final IHttpRequestResponse baseMessage) {
        final HttpMethod getRequest = new GetRequest(burpHelperDto, baseMessage);
        return getRequest;
    }
}
