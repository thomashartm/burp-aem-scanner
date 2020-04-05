package burp.http;

import burp.IHttpRequestResponse;

/**
 * Provides the results of an HTTP request response execution through a HTTP method such as a GET to a specific URL.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
public class ResponseEntity {

    public enum Status{
        INCOMPLETE, FAILED, SUCCESS
    }

    Status status;

    private final IHttpRequestResponse responseMessage;

    private ResponseEntity() {
        this.responseMessage = null;
        this.status = Status.INCOMPLETE;
    }

    private ResponseEntity(IHttpRequestResponse responseMessage) {
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

    public static ResponseEntity createIncomplete(){
        return new ResponseEntity();
    }

    public static ResponseEntity create(IHttpRequestResponse responseMessage){
        return new ResponseEntity(responseMessage);
    }
}
