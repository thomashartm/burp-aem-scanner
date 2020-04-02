package legacy.actions.http;

import burp.IHttpRequestResponse;

/**
 * Provides information about an HTTP request response execution through an HTTP method.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public class ResponseHolder {

    public enum Status{
        INCOMPLETE, FAILED, SUCCESS
    }

    Status status;

    private final IHttpRequestResponse responseMessage;

    private ResponseHolder() {
        this.responseMessage = null;
        this.status = Status.INCOMPLETE;
    }

    private ResponseHolder(IHttpRequestResponse responseMessage) {
        this.responseMessage = responseMessage;
    }

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
    }

    public IHttpRequestResponse getResponseMessage() {
        return responseMessage;
    }

    public static ResponseHolder createIncomplete(){
        return new ResponseHolder();
    }

    public static ResponseHolder create(IHttpRequestResponse responseMessage){
        return new ResponseHolder(responseMessage);
    }
}
