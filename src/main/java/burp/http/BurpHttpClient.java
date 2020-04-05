package burp.http;

import biz.netcentric.aem.securitycheck.http.HttpClient;
import biz.netcentric.aem.securitycheck.model.HttpMethod;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.data.BurpHelperDto;

public class BurpHttpClient implements HttpClient {

    private final BurpHelperDto helperDto;
    private final IHttpRequestResponse requestResponse;
    private final IHttpService httpService;

    public BurpHttpClient(final BurpHelperDto helperDto, final IHttpRequestResponse requestResponse) {
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
    public RequestDelegate create(HttpMethod method) {

        if(HttpMethod.GET == method){
            return new GetRequest(helperDto, requestResponse);
        }

        if(HttpMethod.POST == method){
            return new PostRequest(helperDto, requestResponse);
        }

        throw new UnsupportedOperationException("Unable to create a method of type " + method.toString());
    }
}
