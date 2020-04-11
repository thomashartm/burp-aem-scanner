package biz.netcentric.aem.securitycheck.dsl

import biz.netcentric.aem.securitycheck.dsl.detection.EvaluationRule
import biz.netcentric.aem.securitycheck.http.ResponseEntity
import biz.netcentric.aem.securitycheck.model.EvaluationResult


/**
 * DSL to process the define and process the evaluation criteria for responses
 *
 * It can be used to evaluate either and/or condition chained expectations
 * {@code
 * {
 *  all {
 *      expect body contains "results"
 *      expect statusCode is 200
 *      expect responseType equals "text/html"
 *  }
 *
 *  oneOf {
 *      expect body contains "prompt("
 *      expect body equals "<img src=x onerror=alert(1)>"
 *  }
 * }
 * }
 *
 */
class EvaluationDsl {

    ResponseEntity response

    List<EvaluationResult> allGroup = []

    List<EvaluationResult> oneOfGroup = []

    EvaluationDsl(ResponseEntity response) {
        this.response = response
    }

    def all(@DelegatesTo(strategy = Closure.DELEGATE_FIRST, value = EvaluationRule) Closure closure) {
        List<EvaluationResult> results = executeEvaluationClosure(closure)
        this.allGroup.addAll(results)
    }

    def oneOf(@DelegatesTo(strategy = Closure.DELEGATE_FIRST, value = EvaluationRule) Closure closure) {
        List<EvaluationResult> results = executeEvaluationClosure(closure)
        this.oneOfGroup.addAll(results)
    }

    private List<EvaluationResult> executeEvaluationClosure(Closure closure) {
        EvaluationRule rule = new EvaluationRule(this.response)
        closure.setDelegate(rule)
        closure.setResolveStrategy(Closure.DELEGATE_FIRST)

        closure()

        List<EvaluationResult> results = closure.getResult()

        results
    }
}