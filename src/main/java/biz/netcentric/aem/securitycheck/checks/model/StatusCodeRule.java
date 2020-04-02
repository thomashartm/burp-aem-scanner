package biz.netcentric.aem.securitycheck.checks.model;

public class StatusCodeRule  implements EvaluationRule{

    private int code;

    private Operator operator;

    public StatusCodeRule(int code, Operator operator) {
        this.code = code;
        this.operator = operator;
    }

    public static StatusCodeRule equalsRule(final int statusCode){
        return new StatusCodeRule(statusCode, Operator.EQUAL);
    }

    public static StatusCodeRule notEqualsRule(final int statusCode){
        return new StatusCodeRule(statusCode, Operator.NOT_EQUAL);
    }

    public static StatusCodeRule largerThenRule(final int statusCode){
        return new StatusCodeRule(statusCode, Operator.LARGER);
    }

    public static StatusCodeRule smallerThenRule(final int statusCode){
        return new StatusCodeRule(statusCode, Operator.SMALLER);
    }

    enum Operator{
        EQUAL, NOT_EQUAL, LARGER, SMALLER;
    }
}
