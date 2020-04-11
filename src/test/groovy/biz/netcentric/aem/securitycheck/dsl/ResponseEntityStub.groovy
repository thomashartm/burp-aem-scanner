package biz.netcentric.aem.securitycheck.dsl

import biz.netcentric.aem.securitycheck.http.Cookie
import biz.netcentric.aem.securitycheck.http.ResponseEntity
import lombok.Builder

@Builder
class ResponseEntityStub implements ResponseEntity{

    String messageBody

    int statusCode

    String mimeType

    List<String> headers

    List<Cookie> cookies;

    @Override
    String getMessageBody() {
        return this.messageBody
    }

    @Override
    byte[] getRawResponse() {
        return messageBody.getBytes()
    }

    @Override
    int getStatusCode() {
        return this.statusCode
    }

    @Override
    String getMimeType() {
        return this.mimeType
    }

    @Override
    List<String> getHeaders() {
        return this.headers
    }

    @Override
    List<Cookie> getCookies() {
        return this.cookies
    }
}
