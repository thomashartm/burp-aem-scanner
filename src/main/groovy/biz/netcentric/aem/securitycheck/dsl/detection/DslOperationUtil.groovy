package biz.netcentric.aem.securitycheck.dsl.detection

import biz.netcentric.aem.securitycheck.model.EvaluationResult

class DslOperationUtil {

    static EvaluationResult createEvaluationResult(String condition, boolean result) {
        EvaluationResult.builder()
                .name(condition)
                .isMatch(result)
                .build()
    }
}