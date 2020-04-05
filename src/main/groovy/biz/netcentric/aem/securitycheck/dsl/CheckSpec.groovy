package biz.netcentric.aem.securitycheck.dsl

import biz.netcentric.aem.securitycheck.model.SecurityCheck
import biz.netcentric.aem.securitycheck.model.Vulnerability

class CheckSpec {

    SecurityCheck securityCheck;

    CheckSpec(){
        this.securityCheck = new SecurityCheck()
    }

    SecurityCheck toSecurityCheck(){
        return this.securityCheck
    }

    static SecurityCheck check(@DelegatesTo(strategy = Closure.OWNER_FIRST, value = CheckSpec) Closure closure) {
        assert closure != null

        CheckSpec spec = new CheckSpec()
        closure.setDelegate(spec)
        closure.setResolveStrategy(Closure.OWNER_FIRST)

        closure()

        spec.toSecurityCheck()
    }

    void request(@DelegatesTo(strategy = Closure.OWNER_FIRST, value = RequestSpec) Closure closure){
        assert closure != null

        RequestSpec spec = new RequestSpec()
        closure.setDelegate(spec)
        closure.setResolveStrategy(Closure.OWNER_FIRST)

        closure()

        this.securityCheck.addSecurityCheckRequest(spec.getRequest())
    }

    def id(String id){
        assert id != null
        this.securityCheck.setId(id)
    }

    def categories(String... categories) {
        this.securityCheck.setCategories(Arrays.asList(categories))
    }

    def categories(List<String> categories) {
        this.securityCheck.setCategories(categories)
    }

    def description(@DelegatesTo(strategy = Closure.OWNER_FIRST, value = Vulnerability) Closure closure){

    }
}
