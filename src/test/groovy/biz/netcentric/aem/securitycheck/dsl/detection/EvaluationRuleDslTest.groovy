package biz.netcentric.aem.securitycheck.dsl.detection

import biz.netcentric.aem.securitycheck.dsl.ResponseEntityStub
import biz.netcentric.aem.securitycheck.dsl.detection.EvaluationRuleDsl
import biz.netcentric.aem.securitycheck.model.EvaluationResult
import org.junit.Assert
import org.junit.jupiter.api.Test

class EvaluationRuleDslTest {

    @Test
    void evaluateHeaderMatches() {
        ResponseEntityStub responseEntity = new ResponseEntityStub(
                headers: ["X-NODEID: dispatcher"]
        )

        List<EvaluationResult> results = executeEvaluationClosure responseEntity, {
            expect headers contains "dispatcher"
        }

        Assert.assertTrue results.get(0).isMatch()
    }

    @Test
    void evaluateHeaderMatchesRegexPattern() {
        ResponseEntityStub responseEntity = new ResponseEntityStub(
                headers: ["ContentType: application/json", "X-NODEID: dispatcher", "ContentLength: 4450"]
        )

        List<EvaluationResult> results = executeEvaluationClosure responseEntity, {
            expect headers matches ".*\\sdisp.*"
            expect headers equals "ContentType: application/jsonp", "ContentType: application/json"
            expect headers is "ContentLength: 5000"
        }

        Assert.assertTrue results.get(0).isMatch() // regex match must be true
        Assert.assertTrue results.get(1).isMatch() // equals match must be true because of json ContentType
        Assert.assertFalse results.get(2).isMatch() // is must fail as it expects a larger ContentLength
    }

    @Test
    void evaluateCookieContains() {
        ResponseEntityStub responseEntity = new ResponseEntityStub(
                headers: ["ContentType: application/json", "X-NODEID: dispatcher", "ContentLength: 4450"],
                cookies: [new CookieStub(name: "AWSLB", value: "32424234242432"),
                          new CookieStub(name: "Authentication", value: "13243fdafdsf322343r42", path: "/", domain: "github.com")]
        )

        List<EvaluationResult> results = executeEvaluationClosure responseEntity, {
            cookie name: "Authentication" exists
        }

        Assert.assertTrue results.get(0).isMatch() // regex match must be true
        Assert.assertTrue results.size() == 1

        List<EvaluationResult> resultsWithExpect = executeEvaluationClosure responseEntity, {
            expect cookie "Authentication" exists
        }

    }

    @Test
    void evaluateSpecificCookieWithValue() {
        ResponseEntityStub responseEntity = new ResponseEntityStub(
                headers: ["ContentType: application/json", "X-NODEID: dispatcher", "ContentLength: 4450"],
                cookies: [new CookieStub(name: "AWSLB", value: "32424234242432"),
                          new CookieStub(name: "Authentication", value: "13243fdafdsf322343r42", path: "/", domain: "github.com"),
                          new CookieStub(name: "adobe-analytics", value: "bfsjfsdjfsdkfl", path: "/", domain: "adobe.com")
                ]
        )

        List<EvaluationResult> results = executeEvaluationClosure responseEntity, {
            cookie name: "Authentication" property "domain" equals "github.com"
            cookie name: "adobe-analytics" with "domain" contains "adobe"
        }

        Assert.assertTrue results.get(0).isMatch() // regex match must be true
        Assert.assertTrue results.get(1).isMatch() // regex match must be true
    }

    private List<EvaluationResult> executeEvaluationClosure(ResponseEntityStub responseEntity, Closure closure) {
        EvaluationRuleDsl rule = new EvaluationRuleDsl(responseEntity)
        closure.setDelegate(rule)
        closure.setResolveStrategy(Closure.DELEGATE_FIRST)

        closure()

        List<EvaluationResult> results = closure.getResult()

        results
    }
}
