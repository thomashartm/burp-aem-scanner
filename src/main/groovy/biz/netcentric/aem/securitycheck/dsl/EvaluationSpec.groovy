package biz.netcentric.aem.securitycheck.dsl

import biz.netcentric.aem.securitycheck.checks.model.EvaluationCriteria
import biz.netcentric.aem.securitycheck.checks.model.RuleEvaluationType
import org.apache.commons.lang3.StringUtils

class EvaluationSpec {

    EvaluationCriteria evaluationCriteria;

    EvaluationSpec() {
        this.evaluationCriteria = new EvaluationCriteria()
    }

    void matches(RuleEvaluationType evaluationType) {
        this.evaluationCriteria.setRuleEvaluationType(evaluationType)
    }

    void expect(String criteria, String operator, String... values) {
        assert criteria != null
        assert operator != null


        if (isMatch(operator, "body", "message", "response")) {
            if (isMatch(operator, "is", "matches")) {
                expectAllInBody(values)
            } else {
                expectOneInBody(values)
            }
            return;
        }

        if (isMatch(criteria, "status", "statuscode", "code")) {
            int code = Integer.valueOf(values[0])
            if (isMatch(operator, "is", "matches", "equals")) {
                statusCode(code)
            } else {
                statusCodeIsNot(code)
            }
            return;
        }

    }

    boolean isMatch(String criteria, String... matches) {
        return StringUtils.equalsAny(criteria.toLowerCase(), matches)
    }

    void expectOneInBody(String... tokens) {
        this.evaluationCriteria.addBodyContainsAnyRule(tokens)
    }

    void expectAllInBody(String... tokens) {
        this.evaluationCriteria.addBodyContainsAllRule(tokens)
    }

    void statusCode(int statusCode) {
        this.evaluationCriteria.addStatusCodeEquals(statusCode);
    }

    void statusCodeIsNot(int statusCode) {
        this.evaluationCriteria.addStatusCodeNotEquals(statusCode);
    }

}