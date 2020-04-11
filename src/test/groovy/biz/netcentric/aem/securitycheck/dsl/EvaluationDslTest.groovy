package biz.netcentric.aem.securitycheck.dsl


import biz.netcentric.aem.securitycheck.http.Cookie
import biz.netcentric.aem.securitycheck.http.ResponseEntity
import org.junit.jupiter.api.Test

class EvaluationDslTest {

    @Test
    void all() {
        ResponseEntity responseEntity = new ResponseEntity(){

            private String body = "{results: [xxx:yyy], total: 1}";
            @Override
            String getMessageBody() {
                return body
            }

            @Override
            byte[] getRawResponse() {
                return body.getBytes()
            }

            @Override
            int getStatusCode() {
                return 200
            }

            @Override
            String getMimeType() {
                return "application/json"
            }

            @Override
            List<String> getHeaders() {
                return []
            }

            @Override
            List<Cookie> getCookies() {
                return []
            }
        }

        EvaluationDsl dsl = new EvaluationDsl(responseEntity)

        dsl.all {
            expect body contains "results"
            expect status is 200
        }

        // TODO expect that all rules are evaluated
    }

    @Test
    void oneOf() {
    }
}
