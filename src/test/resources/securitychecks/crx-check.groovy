package securitychecks

check {

    id "CRX Test"

    categories "xss", "ssrf", "xxe"

    request {

        paths "/content", "/etc", "/apps"

        selectors "1", "2"

        extensions ".xml", ".json"

        evaluate {

        }
    }

    request {

        paths "/content", "/etc", "/apps"

        selectors "1", "2"

        extensions ".xml", ".json"

        evaluate {

        }
    }

    print "Executed test script"

}