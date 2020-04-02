package biz.netcentric.aem.securitycheck.checks.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class SecurityCheckRequest {

    private String method;

    private String referrer;

    private List<String> requestHeader;

    private List<String> paths;

    private List<String> selectors;

    private List<String> extensions;

    private EvaluationCriteria evaluationCriteria;

    /*
    - name: "GET /crx/de"
    method: "GET"
    paths:
            - "/crx/de"
            - "/crx/de/index.jsp"
    extensions:
            - ".json"
    requestHeaders:
    host: "example.com"
    Referer: "referer.example.com"
    authenticationHeaders:
    authentication: "Basic xyz"
    params:
    param1: "value1"
    param2: "value2"
    detect:
            - type: all
    expectedStatusCode: 200
    bodyContains:
            - "CRX"
            - "Explorer"

     */
}
