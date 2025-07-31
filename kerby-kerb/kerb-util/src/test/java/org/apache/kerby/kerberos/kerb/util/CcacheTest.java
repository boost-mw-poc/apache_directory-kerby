/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.kerby.kerberos.kerb.util;

import org.apache.kerby.kerberos.kerb.ccache.CredCacheInputStream;
import org.apache.kerby.kerberos.kerb.ccache.CredCacheOutputStream;
import org.apache.kerby.kerberos.kerb.ccache.Credential;
import org.apache.kerby.kerberos.kerb.ccache.CredentialCache;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationData;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationDataEntry;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationType;
import org.apache.kerby.kerberos.kerb.type.base.HostAddress;
import org.apache.kerby.kerberos.kerb.type.base.HostAddresses;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.InetAddress;

import static org.assertj.core.api.Assertions.assertThat;

/*
Default principal: drankye@SH.INTEL.COM

Valid starting       Expires              Service principal
08/05/2014 00:13:17  08/05/2014 10:13:17  krbtgt/SH.INTEL.COM@SH.INTEL.COM
        Flags: FIA, Etype (skey, tkt): des3-cbc-sha1, des3-cbc-sha1
 */
public class CcacheTest {

    private CredentialCache cc;

    @BeforeEach
    public void setUp() throws IOException {
        try (InputStream cis = CcacheTest.class.getResourceAsStream("/test.cc")) {
            cc = new CredentialCache();
            cc.load(cis);
        }
    }

    @Test
    public void testCc() {
        assertThat(cc).isNotNull();

        PrincipalName princ = cc.getPrimaryPrincipal();
        assertThat(princ).isNotNull();
        assertThat(princ.getName().equals("drankye@SH.INTEL.COM")).isTrue();
    }

    @Test
    public void testHostAddresses() throws Exception {
        Credential cred = cc.getCredentials().get(0);
        assertThat(cred).isNotNull();

        assertThat(cred.getClientAddresses()).isNull();
        // Mock up a HostAddresses object
        HostAddresses addresses = new HostAddresses();
        addresses.add(new HostAddress(InetAddress.getLocalHost()));

        // Use reflection to set the client addresses
        Field field = Credential.class.getDeclaredField("clientAddresses");
        field.setAccessible(true);
        field.set(cred, addresses);
        assertThat(cred.getClientAddresses()).isNotNull();

        // Serialize the Credential object
        OutputStream outputStream = new ByteArrayOutputStream();
        CredCacheOutputStream ccos = new CredCacheOutputStream(outputStream);
        cred.store(ccos, 1);
        ccos.close();

        // Deserialize the Credential object
        InputStream inputStream = new ByteArrayInputStream(((ByteArrayOutputStream) outputStream).toByteArray());
        CredCacheInputStream ccis = new CredCacheInputStream(inputStream);
        Credential newCred = new Credential();
        newCred.load(ccis, 1);

        assertThat(newCred.getClientAddresses()).isNotNull();
        assertThat(newCred.getClientAddresses().getElements().get(0).getAddress())
                .isEqualTo(InetAddress.getLocalHost().getAddress());
    }

    @Test
    public void testAuthzData() throws Exception {
        Credential cred = cc.getCredentials().get(0);
        assertThat(cred).isNotNull();

        // Mock up an AuthorizationData object
        AuthorizationData authzData = new AuthorizationData();
        AuthorizationDataEntry entry = new AuthorizationDataEntry();
        entry.setAuthzType(AuthorizationType.AD_KDC_ISSUED);
        entry.setAuthzData("Test data".getBytes());
        authzData.add(entry);

        // Use reflection to set the authzData
        Field field = Credential.class.getDeclaredField("authzData");
        field.setAccessible(true);
        field.set(cred, authzData); // Set the authzData field
        assertThat(cred.getAuthzData()).isNotNull();

        // Serialize the Credential object
        OutputStream outputStream = new ByteArrayOutputStream();
        CredCacheOutputStream ccos = new CredCacheOutputStream(outputStream);
        cred.store(ccos, 1);
        ccos.close();

        // Deserialize the Credential object
        InputStream inputStream = new ByteArrayInputStream(((ByteArrayOutputStream) outputStream).toByteArray());
        CredCacheInputStream ccis = new CredCacheInputStream(inputStream);
        Credential newCred = new Credential();
        newCred.load(ccis, 1);
        
        assertThat(newCred.getAuthzData()).isNotNull();
        assertThat(newCred.getAuthzData().getElements().get(0).getAuthzType())
                .isEqualTo(AuthorizationType.AD_KDC_ISSUED);
        assertThat(newCred.getAuthzData().getElements().get(0).getAuthzData())
                .isEqualTo("Test data".getBytes());
        
    }
}
