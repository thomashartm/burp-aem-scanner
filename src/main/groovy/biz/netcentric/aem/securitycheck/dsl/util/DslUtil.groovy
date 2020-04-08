package biz.netcentric.aem.securitycheck.dsl.util

import groovy.transform.CompileStatic

@CompileStatic
class DslUtil {

    /**
     * Calls a function with a parameter, then returns the parameter.
     * This simplifies the repeated usage of this pattern:
     *
     * {@code
     * def thing = new Thing()
     * parent.things(thing)
     * return thing
     * }
     *
     * to:
     *
     * {@code call(new Thing(), parent.&things) }
     *
     * @param thing
     * @param callback
     * @return
     */
    static <T> T call(T thing, Closure callback) {
        callback.call(thing)

        thing
    }

    /**
     * Runs the closure, using the provided delegate.
     *
     * @param closure
     * @param delegate
     * @return
     */
    static <T> T runWithDelegate(Closure closure, T delegate) {
        closure.delegate = delegate
        closure.resolveStrategy = Closure.DELEGATE_FIRST
        closure()

        delegate
    }
}