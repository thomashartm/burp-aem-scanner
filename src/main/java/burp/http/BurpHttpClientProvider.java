package burp.http;

import biz.netcentric.aem.securitycheck.HttpClientProvider;
import biz.netcentric.aem.securitycheck.model.HttpMethod;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.data.BurpHelperDto;

import java.net.MalformedURLException;
import java.net.URL;

public class BurpHttpClientProvider implements HttpClientProvider {

    private final BurpHelperDto helperDto;
    private final IHttpRequestResponse requestResponse;
    private final IHttpService httpService;

    public BurpHttpClientProvider(final BurpHelperDto helperDto, final IHttpRequestResponse requestResponse) {
        this.helperDto = helperDto;
        this.requestResponse = requestResponse;
        this.httpService = requestResponse.getHttpService();

    }

    public BurpHelperDto getHelperDto() {
        return helperDto;
    }

    public IHttpRequestResponse getRequestResponse() {
        return requestResponse;
    }

    @Override
    public RequestDelegate createRequestDelegate(HttpMethod method) {

        if(HttpMethod.GET == method){
            return new GetRequest(helperDto, requestResponse);
        }

        if(HttpMethod.POST == method){
            return new PostRequest(helperDto, requestResponse);
        }

        throw new UnsupportedOperationException("Unable to create a method of type " + method.toString());
    }

    @Override
    public URL createUrl(final String path) throws MalformedURLException {
        return new URL(this.httpService.getProtocol(), this.httpService.getHost(), this.httpService.getPort(), path);
    }
}
