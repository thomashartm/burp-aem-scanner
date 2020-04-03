package biz.netcentric.aem.securitycheck.checks.model;

import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;


/**

 id: "crx-1"
 categories:
 - "dispatcher"
 - "checkerdsl"
 vulnerability:
 name: "Information Disclosure"
 description: "CRX should not be accessible"
 remediation: "Block CRX access through AEM dispatcher rules."
 cve: ""
 severity: "HIGH"
 steps:
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


@Getter
@Setter
public class SecurityCheck {

    private String id;

    private List<String> categories;

    private Vulnerability vulnerability;

    private List<SecurityCheckRequest> requestSteps;

    public SecurityCheck() {
        this.requestSteps = new ArrayList<>();
    }

    public void addSecurityCheckRequest(SecurityCheckRequest securityCheckRequest){
        this.requestSteps.add(securityCheckRequest);
    }
}