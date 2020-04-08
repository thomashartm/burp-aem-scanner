package biz.netcentric.aem.securitycheck.dsl

import biz.netcentric.aem.securitycheck.model.SecurityCheck
import biz.netcentric.aem.securitycheck.model.Vulnerability

class CheckDsl {

    SecurityCheck securityCheck;

    CheckDsl(){
        this.securityCheck = new SecurityCheck()
    }

    SecurityCheck toSecurityCheck(){
        return this.securityCheck
    }

    static SecurityCheck check(@DelegatesTo(strategy = Closure.OWNER_FIRST, value = CheckDsl) Closure closure) {
        assert closure != null

        CheckDsl dsl = new CheckDsl()
        closure.setDelegate(dsl)
        closure.setResolveStrategy(Closure.OWNER_FIRST)

        closure()

        dsl.toSecurityCheck()
    }

    void request(@DelegatesTo(strategy = Closure.OWNER_FIRST, value = RequestDsl) Closure closure){
        assert closure != null

        RequestDsl dsl = new RequestDsl()
        closure.setDelegate(dsl)
        closure.setResolveStrategy(Closure.OWNER_FIRST)

        closure()

        this.securityCheck.addSecurityCheckRequest(dsl.getRequest())
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
