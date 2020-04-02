package biz.netcentric.aem.securitycheck.checks.service;

import biz.netcentric.aem.securitycheck.checks.model.SecurityCheck;
import biz.netcentric.aem.securitycheck.files.SourceFile;
import biz.netcentric.aem.securitycheck.files.FileSystemResourceLoader;

import java.util.Collections;
import java.util.List;

public class CheckProvider {

    private final FileSystemResourceLoader filesystemResourceLoader;

    public CheckProvider() {
        filesystemResourceLoader = new FileSystemResourceLoader();
    }

    public List<SecurityCheck> loadChecks(final String path){
        final List<SourceFile> specs = filesystemResourceLoader.loadFiles(path);

        return Collections.emptyList();
    }

    protected SecurityCheck createCheck(final SourceFile sourceFile){

        return null;
    }
}
