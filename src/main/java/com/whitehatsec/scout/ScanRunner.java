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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.CookieStore;
import org.apache.http.client.HttpClient;
import org.apache.http.client.fluent.Executor;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.fluent.Response;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.maven.plugin.MojoExecutionException;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.joda.time.format.*;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

class ScanRunner {

    private final ProgressLogger progressLogger;
    private final String username;
    private final String password;
    private final URI scoutUri;
    private final String[] inclusions;
    private final String[] exclusions;
    private final File scanFile;
    private final String tag;
    private final ObjectMapper mapper;
    private final Executor executor;

    private ScanRunner(ProgressLogger progressLogger, boolean disableCertValidation, URI scoutUri, String username, String password, File scanFile, String tag, String[] inclusions, String[] exclusions) throws MojoExecutionException {
        this.progressLogger = progressLogger;
        this.scoutUri = scoutUri;
        this.username = username;
        this.password = password;
        this.scanFile = scanFile;
        this.tag = tag;
        this.inclusions = inclusions;
        this.exclusions = exclusions;

        CookieStore cookieStore = new BasicCookieStore();

        HttpClientBuilder builder = HttpClientBuilder.create()
                .setDefaultCookieStore(cookieStore);

        if (disableCertValidation) {
            TrustManager[] myTMs = new TrustManager[]{
                    new X509TrustManager() {
                        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                        }

                        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                        }

                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }
                    }
            };

            SSLContext sslContext;

            try {
                sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, myTMs, null);
            } catch (GeneralSecurityException e) {
                throw new MojoExecutionException("Failed to initialize TLS transport");
            }

            builder.setSSLContext(sslContext);
        }

        HttpClient httpClient = builder.build();

        this.executor = Executor.newInstance(httpClient);
        this.mapper = new ObjectMapper();
    }

    ScanFindings execute() throws MojoExecutionException {
        this.login();
        int scanID = this.startScan();
        Rating[] findingRatings = this.waitForScanComplete(scanID);
        this.logout();
        return new ScanFindings(scanID, findingRatings);
    }

    void executeAsync() throws MojoExecutionException {
        this.login();
        this.startScan();
        this.logout();
    }

    private void login() throws MojoExecutionException {
        // Log in to Scout
        try {
            LoginBody loginBody = new LoginBody(this.username, this.password);

            byte[] loginBodyBytes = this.mapper.writeValueAsBytes(loginBody);

            URI loginURI = this.scoutUri.resolve("/api/login");
            Response response = this.executor.execute(Request.Post(loginURI).setHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType()).bodyByteArray(loginBodyBytes));
            if (response.returnResponse().getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                throw new MojoExecutionException("Failed to log into WhiteHat Security Scout");
            }
        } catch (IOException e) {
            throw new MojoExecutionException("Failed to send login request to WhiteHat Security Scout Server", e);
        }
    }

    private int startScan() throws MojoExecutionException {
        // Get scan history
        try {
            NewScanBody newScanBody = new NewScanBody(
                    this.scanFile.getName(),
                    this.tag,
                    this.inclusions,
                    this.exclusions
            );

            this.progressLogger.log(String.format("Verifying artifact %s", newScanBody.filename));

            byte[] newScanBodyBytes = this.mapper.writeValueAsBytes(newScanBody);

            URI newScansURI = this.scoutUri.resolve("/api/scans");
            Response response = this.executor.execute(Request.Post(newScansURI).setHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType()).bodyByteArray(newScanBodyBytes));
            HttpResponse httpResponse = response.returnResponse();
            if (httpResponse.getStatusLine().getStatusCode() != HttpStatus.SC_CREATED) {
                throw new MojoExecutionException("Failed to create new scan with WhiteHat Security Scout");
            }
            JsonNode responseBody = this.mapper.readTree(httpResponse.getEntity().getContent());
            String putURLString = responseBody.get("putURL").asText();
            URI putURL = URI.create(putURLString);

            int scanID = responseBody.get("id").asInt();

            URI uploadFileURI = this.scoutUri.resolve("/api/uploadFile" + putURL.getPath() + "?" + putURL.getQuery());

            response = this.executor.execute(Request.Put(uploadFileURI).bodyFile(this.scanFile, ContentType.APPLICATION_OCTET_STREAM));

            if (response.returnResponse().getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                throw new MojoExecutionException("Failed to upload artifact to WhiteHat Security Scout");
            }

            this.progressLogger.log("Artifact uploaded");

            return scanID;
        } catch (IOException e) {
            throw new MojoExecutionException("Failed to create new scan with WhiteHat Security Scout", e);
        }
    }

    private Rating[] waitForScanComplete(int scanID) throws MojoExecutionException {
        ScanStatus previousStatus = null;
        ScanStatus currentStatus;
        do {
            currentStatus = getScanStatus(scanID);
            if (previousStatus != currentStatus) {
                if (currentStatus.displayName() != null) {
                    this.progressLogger.log(String.format("%s", currentStatus.displayName()));
                }
            }
            previousStatus = currentStatus;
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                // Ignoring exception, if the thread was interrupted then request will be send
                // earlier than expected, no harm done
            }
        } while (!currentStatus.isComplete());

        if (!currentStatus.isSuccess()) {
            throw new MojoExecutionException("WhiteHat Scout failed to scan artifact");
        }

        ScanStats scanStats = getScanStats(scanID);
        PeriodFormatter periodFormatter = new PeriodFormatterBuilder().appendMinutes().appendSuffix("m").appendSeconds().appendSuffix("s").printZeroRarelyLast().toFormatter();
        this.progressLogger.log(String.format("Artifact scanned in [%s]", periodFormatter.print(scanStats.getDuration().toPeriod())));

        return this.getScanFindingRatings(scanID);
    }

    private ScanStatus getScanStatus(int scanID) throws MojoExecutionException {
        URI getScanURI = this.scoutUri.resolve("/api/scans/").resolve(Integer.toString(scanID));

        try {
            Response response = this.executor.execute(Request.Get(getScanURI));
            HttpResponse httpResponse = response.returnResponse();

            if (httpResponse.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                throw new MojoExecutionException("Failed to retrieve scan status from WhiteHat Security Scout");
            }
            JsonNode responseBody = this.mapper.readTree(httpResponse.getEntity().getContent());
            String scanStatusString = responseBody.get("status").asText();

            return ScanStatus.fromStatus(scanStatusString);
        } catch (IOException e) {
            throw new MojoExecutionException("Failed to retrieve scan status from WhiteHat Security Scout", e);
        }
    }

    private ScanStats getScanStats(int scanID) throws MojoExecutionException {
        URI getScanURI = this.scoutUri.resolve("/api/scans/").resolve(Integer.toString(scanID));

        try {
            Response response = this.executor.execute(Request.Get(getScanURI));
            HttpResponse httpResponse = response.returnResponse();

            if (httpResponse.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                throw new MojoExecutionException("Failed to retrieve scan status from WhiteHat Security Scout");
            }
            JsonNode responseBody = this.mapper.readTree(httpResponse.getEntity().getContent());
            String createdOn = responseBody.get("createdOn").asText();
            String completedOn = responseBody.get("completedOn").asText();

            DateTimeFormatter formatter = ISODateTimeFormat.dateTime();
            DateTime createdOnDateTime = formatter.parseDateTime(createdOn);
            DateTime completedOnDateTime = formatter.parseDateTime(completedOn);
            Duration scanDuration = new Duration(createdOnDateTime, completedOnDateTime);

            return new ScanStats(scanDuration);
        } catch (IOException e) {
            throw new MojoExecutionException("Failed to retrieve scan status from WhiteHat Security Scout", e);
        }
    }

    private Rating[] getScanFindingRatings(int scanID) throws MojoExecutionException {
        URI getFindingsURI = this.scoutUri.resolve("/api/findings");
        URIBuilder uriBuilder = new URIBuilder(getFindingsURI).addParameter("scanID", Integer.toString(scanID));
        try {
            getFindingsURI = uriBuilder.build();
        } catch (URISyntaxException e) {
            throw new MojoExecutionException("Failed to create URI", e);
        }

        try {
            Response response = this.executor.execute(Request.Get(getFindingsURI));
            HttpResponse httpResponse = response.returnResponse();

            if (httpResponse.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                throw new MojoExecutionException("Failed to retrieve scan findings from WhiteHat Security Scout");
            }
            JsonNode responseBody = this.mapper.readTree(httpResponse.getEntity().getContent());

            int vulnCount = responseBody.get("page").get("totalCount").asInt();

            this.progressLogger.log(String.format("%d security findings detected during scan", vulnCount));

            JsonNode collection = responseBody.get("collection");

            Rating[] allRatings = Rating.values();
            int[] ratingsCount = new int[allRatings.length];

            Rating[] ratings = new Rating[vulnCount];

            for (int i = 0; i < vulnCount; i++) {
                ratings[i] = Rating.fromRisk(collection.get(i).get("risk").asInt());
                ratingsCount[ratings[i].ordinal()]++;
            }


            for (int i = allRatings.length - 1; i >= 0; i--) {
                Rating r = allRatings[i];
                if (ratingsCount[r.ordinal()] > 0) {
                    this.progressLogger.log(String.format("Detected %d finding(s) with %s rating", ratingsCount[r.ordinal()], r.getDisplayName()));
                }
            }

            return ratings;
        } catch (IOException e) {
            throw new MojoExecutionException("Failed to retrieve scan status from WhiteHat Security Scout", e);
        }
    }

    private void logout() throws MojoExecutionException {
        try {
            URI logoutURI = this.scoutUri.resolve("/api/logout");
            Response response = this.executor.execute(Request.Post(logoutURI).setHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType()));
            if (response.returnResponse().getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                throw new MojoExecutionException("Failed to log out from WhiteHat Security Scout");
            }
        } catch (IOException e) {
            throw new MojoExecutionException("Failed to send logout request to WhiteHat Security Scout Server", e);
        }
    }

    public static final class LoginBody {
        private String username;
        private String password;

        private LoginBody(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String getUsername() {
            return username;
        }

        public String getPassword() {
            return password;
        }
    }

    public static final class NewScanBody {
        private String filename;
        private String tag;
        private String[] includePkgFilter;
        private String[] excludePkgFilter;

        private NewScanBody(String filename, String tag, String[] includePkgFilter, String[] excludePkgFilter) {
            this.filename = filename;
            this.tag = tag;
            this.includePkgFilter = includePkgFilter;
            this.excludePkgFilter = excludePkgFilter;
        }

        public String getFilename() {
            return filename;
        }

        public String getTag() {
            return tag;
        }

        public String[] getIncludePkgFilter() {
            return includePkgFilter;
        }

        public String[] getExcludePkgFilter() {
            return excludePkgFilter;
        }
    }

    static final class Builder {
        private ProgressLogger progressLogger;
        private URI scoutUri;
        private boolean disableCertValidation;
        private String username;
        private String password;
        private File scanFile;
        private String tag;
        private String[] inclusions;
        private String[] exclusions;

        ScanRunner build() throws MojoExecutionException {
            return new ScanRunner(this.progressLogger, this.disableCertValidation, this.scoutUri, this.username, this.password, this.scanFile, this.tag, this.inclusions, this.exclusions);
        }

        Builder withProgressLogger(ProgressLogger progressLogger) {
            this.progressLogger = progressLogger;
            return this;
        }

        Builder withUsername(String username) {
            this.username = username;
            return this;
        }

        Builder withPassword(String password) {
            this.password = password;
            return this;
        }

        Builder withScoutUri(URI scoutUri) {
            this.scoutUri = scoutUri;
            return this;
        }

        Builder withInclusions(String[] inclusions) {
            this.inclusions = inclusions;
            return this;
        }

        Builder withExclusions(String[] exclusions) {
            this.exclusions = exclusions;
            return this;
        }

        Builder withScanFile(File scanFile) {
            this.scanFile = scanFile;
            return this;
        }

        Builder withTag(String tag) {
            this.tag = tag;
            return this;
        }

        Builder withDisableCertValidation(boolean disableCertValidation) {
            this.disableCertValidation = disableCertValidation;
            return this;
        }
    }

    static class ScanFindings {
        private int scanID;
        private Rating[] ratings;

        private ScanFindings(int scanID, Rating[] ratings) {
            this.scanID = scanID;
            this.ratings = ratings;
        }

        int getScanID() {
            return this.scanID;
        }

        int getCount() {
            return this.ratings.length;
        }

        Rating[] getRatings() {
            return this.ratings;
        }
    }

    static class ScanStats {
        private Duration duration;

        private ScanStats(Duration duration) {
            this.duration = duration;
        }

        Duration getDuration() {
            return this.duration;
        }
    }

    interface ProgressLogger {
        void log(String progress);
    }
}
