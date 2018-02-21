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

import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.testing.AbstractMojoTestCase;
import org.apache.maven.plugin.testing.stubs.MavenProjectStub;
import org.apache.maven.project.MavenProject;

import java.io.File;

public class ScoutMojoTest extends AbstractMojoTestCase {

    private ScoutMojo mojo;
    private MavenProject project;

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        File testPom = new File( getBasedir(),
                "src/test/resources/test-pom.xml" );

        this.mojo = (ScoutMojo) lookupMojo( "scan", testPom );
        assertNotNull(mojo);

        this.project = new MavenProjectStub();
        setVariableValueToObject( this.mojo, "project", this.project );
        setVariableValueToObject( this.mojo, "authType", ScoutMojo.AuthType.UsernameAndPassword );
    }

    public void testMissingUsernameAndPassword() throws Exception {
        try {
            this.mojo.execute();
            fail("Should have failed with missing username and password");
        } catch (MojoExecutionException e) {
            assertTrue(e.getMessage().contains("username/password"));
        }
    }

    public void testMissingArtifact() throws Exception {
        try {
            setVariableValueToObject(this. mojo, "username", "username" );
            setVariableValueToObject(this. mojo, "password", "password" );
            this.mojo.execute();
            fail("Should have failed with missing artifact");
        } catch (MojoExecutionException e) {
            e.printStackTrace();
            assertTrue(e.getMessage().contains("Could not find artifact to scan"));
        }
    }

}
