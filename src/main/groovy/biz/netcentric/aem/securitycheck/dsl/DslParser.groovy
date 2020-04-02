package biz.netcentric.aem.securitycheck.dsl

import biz.netcentric.aem.securitycheck.checks.model.SecurityCheck
import biz.netcentric.aem.securitycheck.files.FileSystemResourceLoader
import biz.netcentric.aem.securitycheck.files.SourceFile
import org.codehaus.groovy.control.CompilerConfiguration
import org.codehaus.groovy.control.customizers.ImportCustomizer

class DslParser {

    def DEFAULT_IMPORTS = ["biz.netcentric.aem.securitycheck.checks.model", "biz.netcentric.aem.securitycheck.dsl"]

    static void main(String[] args){
        DslParser parser = new DslParser()
        String location = args[0]
        parser.loadScripts(location)
    }

    List<SecurityCheck> loadScripts(String location) {
        FileSystemResourceLoader fsLoader = new FileSystemResourceLoader()
        List<SourceFile> sources = fsLoader.loadFiles(location)

        List<SecurityCheck> checks = new ArrayList<>();
        sources.each { sourceFile ->
            checks.add(buildScript(sourceFile))
        }

        return checks
    }

    SecurityCheck buildScript(SourceFile sourceFile){
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
