package biz.netcentric.aem.securitycheck.dsl.detection

class ResponseAttribute {

    // replace closures by methods to extract the respective property
    static def body(){
        return {response ->
            "body"
        }
    }

    static def status(){
        return {response ->
            "status"
        }
    }

    static def statuscode(){
        return {response ->
            "status"
        }
    }
}