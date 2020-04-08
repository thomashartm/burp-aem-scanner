package biz.netcentric.aem.securitycheck.dsl.detection

import biz.netcentric.aem.securitycheck.model.EvaluationResult
import biz.netcentric.aem.securitycheck.http.HttpRequestResponse
import org.apache.commons.lang3.StringUtils

class EvaluationRule {

    HttpRequestResponse httpRequestResponse

    EvaluationResult result

    String attributeValue

    EvaluationRule expect(String parameter) {

        this
    }

    EvaluationRule expect(ResponseAttribute responseAttribute) {
        this.attributeValue = responseAttribute(httpRequestResponse)
        this
    }

    void contains(String... tokens) {

        boolean containsToken = this.attributeValue != null && StringUtils.containsAny(this.attributeValue, tokens)

        this.result = EvaluationResult.builder()
                .checkId("xxx")
                .name("xxx")
                .result(containsToken)
                .build()
    }


}
