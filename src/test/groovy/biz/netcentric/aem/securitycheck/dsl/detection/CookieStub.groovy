package biz.netcentric.aem.securitycheck.dsl.detection

import biz.netcentric.aem.securitycheck.http.Cookie

class CookieStub implements Cookie {

    String name

    String domain

    String path

    String value

    Date expirationTime

    @Override
    String domain() {
        return this.domain
    }

    @Override
    String path() {
        return this.path
    }

    @Override
    String value() {
        return this.value
    }

    @Override
    String name() {
        return this.name
    }

    @Override
    Date expirationTime() {
        return this.expirationTime
    }

    Map<String, Object> map() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("domain", this.domain);
        properties.put("path", this.path);
        properties.put("value", this.value);
        properties.put("name", this.name);
        return properties;
    }
}
