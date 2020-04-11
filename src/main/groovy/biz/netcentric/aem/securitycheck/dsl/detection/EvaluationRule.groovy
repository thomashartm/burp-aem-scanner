package biz.netcentric.aem.securitycheck.dsl.detection

import biz.netcentric.aem.securitycheck.http.ResponseEntity
import biz.netcentric.aem.securitycheck.model.EvaluationResult
import org.apache.commons.lang3.StringUtils

class EvaluationRule {

    ResponseEntity responseEntity

    List<EvaluationResult> result = []

    String attributeValue

    def body = {
        return responseEntity.getMessageBody()
    }

    def status = {
        return "${responseEntity.statusCode}"
    }

    EvaluationRule(ResponseEntity responseEntity) {
        this.responseEntity = responseEntity
    }

    EvaluationRule expect(String parameter) {

        this
    }

    EvaluationRule expect(Closure responseAttribute) {
        this.attributeValue = responseAttribute(responseEntity)
        this
    }


    void contains(String... tokens) {

        boolean containsToken = this.attributeValue != null && StringUtils.containsAny(this.attributeValue, tokens)


        println this.attributeValue + " -- " +  tokens + " is " + containsToken
        this.result.add(EvaluationResult.builder()
                .result(containsToken)
                .build())
    }

    void equals(String... tokens) {

        boolean equalsAnyToken = this.attributeValue != null && StringUtils.equalsAny(this.attributeValue, tokens)



        this.result.add(EvaluationResult.builder()
                .result(equalsAnyToken)
                .build())
    }

    void is(Object token) {
        boolean isValue = false

        if(token != null){
            isValue = StringUtils.equals(this.attributeValue, String.valueOf(token))
        }

        println this.attributeValue + " -- " +  token + " is " + isValue

        this.result.add(EvaluationResult.builder()
                .result(isValue)
                .build())
    }
}
