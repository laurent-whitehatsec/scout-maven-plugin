// Copyright 2017 WhiteHat Security
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.whitehatsec.scout;

import org.apache.http.client.utils.URIBuilder;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.apache.maven.settings.Server;
import org.apache.maven.settings.Settings;
import org.apache.maven.shared.utils.io.DirectoryScanner;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcher;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcherException;

import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.regex.Pattern;

@Mojo(
        name = "scan",
        defaultPhase = LifecyclePhase.VERIFY
)
public class ScoutMojo extends AbstractMojo {

    private static final String DEFAULT_SCOUT_ADDRESS = "myscan.whitehatsec.com";

    private static final String SCOUT_ADDRESS_KEY = "scout.address";
    private static final String SCOUT_TRACE_HTTP_KEY = "scout.traceHttp";
    private static final String SCOUT_DISABLE_CERT_VALIDATION_KEY = "scout.disableCertValidation";
    private static final String SCOUT_INCLUSIONS_KEY = "scout.inclusions";
    private static final String SCOUT_EXCLUSIONS_KEY = "scout.exclusions";
    private static final String SCOUT_TAG_KEY = "scout.tag";
    private static final String SCOUT_ASYNC_MODE_KEY = "scout.asyncMode";
    private static final String SCOUT_FINDINGS_COUNT_THRESHOLD_KEY = "scout.findingsCountThreshold";
    private static final String SCOUT_FINDINGS_RATING_THRESHOLD_KEY = "scout.findingsRatingThreshold";
    private static final String SCOUT_DISABLE_BROWSER_LAUNCH = "scout.disableBrowserLaunch";
    private static final Pattern VALID_SCAN_TAG_REG_EX = Pattern.compile("^[0-9A-Za-z_.\\- ]{1,100}$");
    private static final Pattern VALID_INCLUDE_EXCLUDE_REG_EX = Pattern.compile("^[0-9A-Za-z_.\\- ]+$");

    /**
     * The Maven project.
     */
    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;

    @Parameter(defaultValue = "${settings}", readonly = true, required = true)
    private Settings settings;

    /**
     * Scout username. If not given, it will be looked up through <code>settings.xml</code>'s server with
     * <code>${settingsKey}</code> as key.
     *
     * @since 1.0
     */
    @Parameter(property = "username")
    private String username;

    /**
     * Scout password. If not given, it will be looked up through <code>settings.xml</code>'s server with
     * <code>${settingsKey}</code> as key.
     *
     * @since 1.0
     */
    @Parameter(property = "password")
    private String password;

    /**
     * Server's <code>id</code> in <code>settings.xml</code> to look up username and password. Defaults to
     * <code>myscan.whitehatsec.com</code> if not given.
     *
     * @since 1.0
     */
    @Parameter(property = "settingsKey")
    private String settingsKey;

    @Component(role = org.sonatype.plexus.components.sec.dispatcher.SecDispatcher.class, hint = "default")
    private SecDispatcher securityDispatcher;

    @Parameter(defaultValue = "${project.build.outputDirectory}")
    private File outputDirectory;

    private static String[] filterList(String filterString) {
        if (filterString == null) {
            return null;
        }

        return filterString.split(",");
    }

    private void enableTraceLogging() {
        Logger logger = Logger.getLogger("");
        logger.setLevel(Level.ALL);
        logger.addHandler(new Handler() {

            @Override
            public void close() throws SecurityException {
            }

            @Override
            public void flush() {
            }

            @Override
            public void publish(LogRecord record) {
                getLog().debug(record.getMessage());
            }
        });

        Logger.getLogger("org.apache.http").setLevel(Level.FINEST);
        Logger.getLogger("org.apache.http.wire").setLevel(Level.FINEST);
    }

    private URI getURI() throws MojoExecutionException {
        String scoutAddress = this.project.getModel().getProperties().getProperty(SCOUT_ADDRESS_KEY, DEFAULT_SCOUT_ADDRESS);
        URI scoutUri;

        try {
            scoutUri = new URIBuilder().setScheme("https").setHost(scoutAddress).build();
        } catch (URISyntaxException e) {
            throw new MojoExecutionException(String.format("Invalid address %s", scoutAddress));
        }

        return scoutUri;
    }

    public void execute() throws MojoExecutionException {

        this.getLog().info("WhiteHat Scout");

        if (Boolean.getBoolean(this.project.getModel().getProperties().getProperty(SCOUT_TRACE_HTTP_KEY, "false"))) {
            enableTraceLogging();
        }

        if (this.settingsKey == null) {
            this.settingsKey = DEFAULT_SCOUT_ADDRESS;
        }

        if ((this.username == null || this.password == null) && (settings != null)) {
            Server server = this.settings.getServer(this.settingsKey);

            if (server != null) {
                if (this.username == null) {
                    this.username = server.getUsername();
                }

                if (this.password == null && server.getPassword() != null) {
                    try {
                        this.password = securityDispatcher.decrypt(server.getPassword());
                    } catch (SecDispatcherException e) {
                        throw new MojoExecutionException(e.getMessage());
                    }
                }
            }
        }

        if (this.password == null || this.username == null) {
            throw new MojoExecutionException("WhiteHat Scout username and password must be provided to upload artifact");
        }

        Properties props = project.getModel().getProperties();

        boolean disableCertValidation = Boolean.parseBoolean(props.getProperty(SCOUT_DISABLE_CERT_VALIDATION_KEY, "false"));

        String[] inclusions = filterList(props.getProperty(SCOUT_INCLUSIONS_KEY));

        if (inclusions != null) {
            for (String inclusion: inclusions) {
                if (!VALID_INCLUDE_EXCLUDE_REG_EX.matcher(inclusion).matches()) {
                    throw new MojoExecutionException("Invalid inclusions property. Provide valid Java package names, Use a comma to separate the items in the list.");
                }
            }
        }

        String[] exclusions = filterList(props.getProperty(SCOUT_EXCLUSIONS_KEY));
        if (exclusions != null) {
            for (String exclusion: exclusions) {
                if (!VALID_INCLUDE_EXCLUDE_REG_EX.matcher(exclusion).matches()) {
                    throw new MojoExecutionException("Invalid exclusions property. Provide valid Java package names, Use a comma to separate the items in the list.");
                }
            }
        }

        String tag = props.getProperty(SCOUT_TAG_KEY);

        if (tag != null && !VALID_SCAN_TAG_REG_EX.matcher(tag).matches()) {
            throw new MojoExecutionException("Invalid tag property. The tag should be 100 characters or less and may use letters, capital letters, and numerals, plus underscore, period, hyphen, and the space character.");
        }

        if (this.outputDirectory != null) {
            Set<String> inclusionSet = new HashSet<>();
            if (inclusions != null) {
                Collections.addAll(inclusionSet, inclusions);
            }

            DirectoryScanner directoryScanner = new DirectoryScanner();
            directoryScanner.addDefaultExcludes();
            directoryScanner.setBasedir(this.outputDirectory);
            directoryScanner.setIncludes("**/*.class");
            directoryScanner.scan();

            String[] paths = directoryScanner.getIncludedFiles();

            for (String p: paths) {
                Path path = Paths.get(p);
                inclusionSet.add(path.getParent().toString().replace(File.separatorChar, '.'));
            }

            inclusions = inclusionSet.toArray(new String[0]);
        }

        Artifact artifact = this.project.getArtifact();

        if (artifact == null || artifact.getFile() == null || !artifact.getFile().exists()) {
            throw new MojoExecutionException("Could not find artifact to scan. Make sure scan goal is executed after after Maven install lifecycle phase");
        }

        URI scoutUri = getURI();

        ScanRunner runner = new ScanRunner.Builder()
                .withProgressLogger(new ScanRunner.ProgressLogger() {
                    @Override
                    public void log(String progress) {
                        getLog().info(progress);
                    }
                })
                .withScoutUri(scoutUri)
                .withDisableCertValidation(disableCertValidation)
                .withUsername(this.username)
                .withPassword(this.password)
                .withScanFile(artifact.getFile())
                .withTag(tag)
                .withInclusions(inclusions)
                .withExclusions(exclusions)
                .build();

        boolean asyncMode = Boolean.parseBoolean(this.project.getModel().getProperties().getProperty(SCOUT_ASYNC_MODE_KEY, "false"));

        if (asyncMode) {
            runner.executeAsync();
            getLog().info(String.format("WhiteHat Scout scan scheduled in asynchronous mode, see results at %s", scoutUri.toASCIIString()));
        } else {
            ScanRunner.ScanFindings findings = runner.execute();

            int findingsCount = findings.getCount();

            Rating findingsRatingThreshold = Rating.fromText(this.project.getModel().getProperties().getProperty(SCOUT_FINDINGS_RATING_THRESHOLD_KEY, "Note"));

            if (findingsRatingThreshold != Rating.Note) {
                findingsCount = 0;
                for (Rating r : findings.getRatings()) {
                    assert findingsRatingThreshold != null;
                    if (r.getRisk() >= findingsRatingThreshold.getRisk()) {
                        findingsCount++;
                    }
                }

                if (findingsCount != findings.getCount()) {
                    getLog().info(String.format("Ignoring %d findings below the configured %s threshold", findings.getCount() - findingsCount, findingsRatingThreshold.getDisplayName()));
                }
            }

            int findingsCountThreshold = Integer.parseInt(this.project.getModel().getProperties().getProperty(SCOUT_FINDINGS_COUNT_THRESHOLD_KEY, "0"));

            URI scanResultsURI;

            try {
                scanResultsURI = new URIBuilder(scoutUri).setPath(String.format("/scan/%d", findings.getScanID())).build();
            } catch (URISyntaxException e) {
                // This exception should never happen, printing stacktrace to help understand why it happened here
                throw new MojoExecutionException("Invalid URI", e);
            }

            if (findingsCount > 0 && findingsCount >= findingsCountThreshold) {
                try {
                    boolean disableBrowserLaunch = Boolean.parseBoolean(this.project.getModel().getProperties().getProperty(SCOUT_DISABLE_BROWSER_LAUNCH, "false"));
                    if (!disableBrowserLaunch && Desktop.isDesktopSupported()) {
                        Desktop.getDesktop().browse(scanResultsURI);
                    }
                    getLog().info(String.format("Findings report available at URL %s", scanResultsURI.toASCIIString()));
                } catch (IOException e) {
                    throw new MojoExecutionException("Failed to launch browser");
                }
                throw new MojoExecutionException(String.format("%d security findings detected during scan", findingsCount));
            } else if (findings.getCount() != 0) {
                getLog().info(String.format("Findings report available at URL %s", scanResultsURI.toASCIIString()));
                getLog().info(String.format("Ignoring scan results with %d findings. Number of findings below configured threshold [%d].", findingsCount, findingsCountThreshold));
            } else {
                getLog().info("WhiteHat Scout: No findings detected");
            }
        }
    }
}