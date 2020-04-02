package securitychecks

check {

    id "CRX Test"

    categories "XYZ", "Test"

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

    print "Hello"

}