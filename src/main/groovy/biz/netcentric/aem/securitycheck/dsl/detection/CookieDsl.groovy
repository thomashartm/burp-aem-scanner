package biz.netcentric.aem.securitycheck.dsl.detection

import biz.netcentric.aem.securitycheck.http.Cookie
import org.apache.commons.lang3.StringUtils

class CookieDsl {

    EvaluationRuleDsl parent

    Cookie cookie

    // setting the property is more or less a DSL hack to enable the groovy DSL statement to null check the containing cookie
    boolean exists

    boolean getExists() {
        boolean cookieExists = cookie != null
        parent.result.add DslOperationUtil.createEvaluationResult("cookie exists", cookieExists)

        return cookieExists
    }

    CookieProperty property(String propertyName) {
        Object propertyValue = (cookie != null) ? cookie.map().get(propertyName) : null
        boolean isEmpty = propertyValue == null

        return new CookieProperty(parent: parent, propertyName: propertyName, propertyValue: propertyValue, isEmpty: isEmpty)
    }

    CookieProperty with(String propertyName) {
        return this.property(propertyName)
    }

    CookieDsl with(Closure closure) {

        this
    }

    class CookieProperty {

        EvaluationRuleDsl parent

        String propertyName

        Object propertyValue

        boolean isEmpty = true

        boolean equals(String value){
            boolean propertyIsEqual = false;

            if (!isEmpty && propertyValue != null && propertyValue instanceof String) {
                propertyIsEqual = StringUtils.equals(value, (String) propertyValue)
            }

            parent.result.add DslOperationUtil.createEvaluationResult("cookie property ${propertyName} equals ${value}", propertyIsEqual)

            propertyIsEqual
        }

        boolean contains(String... values){
            boolean propertyIsEqual = false;

            if (!isEmpty && propertyValue != null && propertyValue instanceof String) {
                propertyIsEqual = StringUtils.containsAny((String) propertyValue, values)
            }

            parent.result.add DslOperationUtil.createEvaluationResult("cookie property ${propertyName} equals ${values}", propertyIsEqual)

            propertyIsEqual
        }
    }
}
