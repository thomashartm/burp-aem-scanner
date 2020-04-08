package biz.netcentric.aem.securitycheck.dsl.detection

class ResponseAttribute {

    // replace closures by methods to extract the respective property
    def body(){
        return {response ->
            "body"
        }
    }

    def status(){
        return {response ->
            "status"
        }
    }
}