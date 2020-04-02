package biz.netcentric.aem.securitycheck.dsl

import biz.netcentric.aem.securitycheck.checks.model.HttpMethod
import biz.netcentric.aem.securitycheck.checks.model.SecurityCheckRequest

class RequestSpec {

    SecurityCheckRequest request

    RequestSpec(){
        this.request = new SecurityCheckRequest()
    }

    static SecurityCheckRequest post(@DelegatesTo(strategy = Closure.OWNER_FIRST, value = RequestSpec) Closure closure) {
        return createAndRunClosure(closure, HttpMethod.POST)
    }

    static SecurityCheckRequest get(@DelegatesTo(strategy = Closure.OWNER_FIRST, value = RequestSpec) Closure closure) {
        return createAndRunClosure(closure, HttpMethod.GET)
    }

    private static RequestSpec createAndRunClosure(Closure closure, HttpMethod method) {
        assert closure != null

        RequestSpec spec = new RequestSpec()
        spec.getRequest().setMethod(method)

        closure.setDelegate(spec)
        closure.setResolveStrategy(Closure.OWNER_FIRST)

        closure()

        spec
    }

    void method(String method){
        this.request.setMethod(method)
    }

    void method(HttpMethod httpMethod){
        this.request.setMethod(httpMethod)
    }

    void referrer(String referrer){
        this.request.setReferrer(referrer)
    }

    void header(String name, String value){

    }

    void selectors(String... selectors){
        this.request.setSelectors(Arrays.asList(selectors))
    }

    void extension(String extension){
        this.request.getExtensions().add(extension)
    }

    void extensions(String... extensions){
        this.request.setExtensions(Arrays.asList(extensions))
    }

    void paths(String... paths){
        this.request.setPaths(Arrays.asList(paths))
    }

    void evaluate(@DelegatesTo(strategy = Closure.OWNER_FIRST, value = EvaluationSpec) Closure closure) {
        EvaluationSpec spec = new EvaluationSpec()
        closure.setDelegate(spec)
        closure.setResolveStrategy(Closure.OWNER_FIRST)

        closure()

        //this.request.setEvaluationCriteria(spec)
    }

    SecurityCheckRequest getRequest(){
        return request;
    }
}
