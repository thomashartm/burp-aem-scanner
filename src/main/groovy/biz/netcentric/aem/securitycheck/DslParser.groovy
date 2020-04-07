package biz.netcentric.aem.securitycheck

import biz.netcentric.aem.securitycheck.files.FileSystemLoader
import biz.netcentric.aem.securitycheck.files.Source
import biz.netcentric.aem.securitycheck.model.SecurityCheck
import org.codehaus.groovy.control.CompilerConfiguration
import org.codehaus.groovy.control.customizers.ImportCustomizer

class DslParser {

    def DEFAULT_IMPORTS = ["biz.netcentric.aem.securitycheck.model", "biz.netcentric.aem.securitycheck.dsl"]

    static void main(String[] args) {
        DslParser parser = new DslParser()
        String location = args[0]
        parser.loadScripts(location)
    }

    List<SecurityCheck> loadScripts(List<String> locations) {
        List<SecurityCheck> checks = new ArrayList<>();
        locations.each {location ->
            checks.addAll(loadScripts(location))
        }

        checks
    }

    List<SecurityCheck> loadScripts(String location) {
        FileSystemLoader fsLoader = new FileSystemLoader()
        List<Source> sources = fsLoader.loadFiles(location)

        List<SecurityCheck> checks = new ArrayList<>()
        sources.each { sourceFile ->
            checks.add(buildScript(sourceFile))
        }

        return checks
    }

    SecurityCheck buildScript(Source sourceFile) {
        CompilerConfiguration compilerConfig = createCompilerConfiguration()
        GroovyShell groovyShell = new GroovyShell(compilerConfig)

        String code = sourceFile.getContent();
        return (SecurityCheck) groovyShell.evaluate("${code}")
        // now check the object and use it
    }

    private CompilerConfiguration createCompilerConfiguration() {
        ImportCustomizer importCustomizer = new ImportCustomizer()
        importCustomizer.addStaticStars("biz.netcentric.aem.securitycheck.dsl.CheckSpec")
        importCustomizer.addStarImports(DEFAULT_IMPORTS.toArray(new String[DEFAULT_IMPORTS.size()]))

        CompilerConfiguration compilerConfig = new CompilerConfiguration()
        compilerConfig.addCompilationCustomizers(importCustomizer)
        compilerConfig
    }
}
