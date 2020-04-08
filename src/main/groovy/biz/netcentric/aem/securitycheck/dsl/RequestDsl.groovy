package biz.netcentric.aem.securitycheck.dsl

import biz.netcentric.aem.securitycheck.model.HttpMethod
import biz.netcentric.aem.securitycheck.model.SecurityCheckRequest

class RequestDsl {

    SecurityCheckRequest request

    RequestDsl(){
        this.request = new SecurityCheckRequest()
    }

    static SecurityCheckRequest post(@DelegatesTo(strategy = Closure.OWNER_FIRST, value = RequestDsl) Closure closure) {
        return createAndRunClosure(closure, HttpMethod.POST)
    }

    static SecurityCheckRequest get(@DelegatesTo(strategy = Closure.OWNER_FIRST, value = RequestDsl) Closure closure) {
        return createAndRunClosure(closure, HttpMethod.GET)
    }

    private static RequestDsl createAndRunClosure(Closure closure, HttpMethod method) {
        assert closure != null

        RequestDsl spec = new RequestDsl()
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

    void evaluate(@DelegatesTo(strategy = Closure.OWNER_FIRST, value = EvaluationDsl) Closure closure) {
        EvaluationDsl spec = new EvaluationDsl()
        closure.setDelegate(spec)
        closure.setResolveStrategy(Closure.OWNER_FIRST)

        closure()

        //this.request.setEvaluationCriteria(spec)
    }

    SecurityCheckRequest getRequest(){
        return request;
    }
}
