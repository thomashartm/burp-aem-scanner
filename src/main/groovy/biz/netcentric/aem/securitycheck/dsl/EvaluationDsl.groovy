package biz.netcentric.aem.securitycheck.dsl

import biz.netcentric.aem.securitycheck.dsl.detection.EvaluationRule
import biz.netcentric.aem.securitycheck.http.HttpRequestResponse

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

    HttpRequestResponse httpRequestResponse

    List<EvaluationRule> allGroup = []

    List<EvaluationRule> oneOfGroup = []

    EvaluationDsl(HttpRequestResponse httpRequestResponse) {
        this.httpRequestResponse = httpRequestResponse
    }

    def all(@DelegatesTo(strategy = Closure.DELEGATE_FIRST, value = EvaluationRule) Closure closure) {
        List<EvaluationRule> results = executeEvaluationClosure(closure)
        this.allGroup.addAll(results)
    }

    def oneOf(@DelegatesTo(strategy = Closure.DELEGATE_FIRST, value = EvaluationRule) Closure closure) {
        List<EvaluationRule> results = executeEvaluationClosure(closure)
        this.oneOfGroup.addAll(results)
    }

    private List<EvaluationRule> executeEvaluationClosure(Closure closure) {
        EvaluationRule evaluator = new EvaluationRule(this.httpRequestResponse)
        closure.setDelegate(evaluator)
        closure.setResolveStrategy(Closure.DELEGATE_FIRST)

        closure()

        List<EvaluationRule> results = closure.getResults()

        results
    }
}