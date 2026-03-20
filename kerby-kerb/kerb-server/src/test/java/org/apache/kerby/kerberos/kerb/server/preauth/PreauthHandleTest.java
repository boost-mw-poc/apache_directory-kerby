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
package org.apache.kerby.kerberos.kerb.server.preauth;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.preauth.PaFlags;
import org.apache.kerby.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerby.kerberos.kerb.server.KdcContext;
import org.apache.kerby.kerberos.kerb.server.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.type.pa.PaData;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataType;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class PreauthHandleTest {

    @Test
    public void verifyShouldPassRequestContextToPlugin() throws KrbException {
        RecordingPreauth preauth = new RecordingPreauth(true);
        PreauthHandle handle = new PreauthHandle(preauth);
        PluginRequestContext requestContext = new PluginRequestContext() { };
        handle.requestContext = requestContext;
        PaDataEntry paDataEntry = new PaDataEntry();

        handle.verify(null, paDataEntry);

        assertThat(preauth.verifyCalled).isTrue();
        assertThat(preauth.capturedRequestContext).isSameAs(requestContext);
        assertThat(preauth.capturedPaData).isSameAs(paDataEntry);
    }
    
    @Test
    public void verifyShouldFailWhenPluginVerifyReturnsFalse() throws KrbException {
        RecordingPreauth preauth = new RecordingPreauth(false);
        PreauthHandle handle = new PreauthHandle(preauth);

        assertThat(handle.verify(null, new PaDataEntry())).isFalse();
    }
    

    private static class RecordingPreauth implements KdcPreauth {
        private final boolean verifyResult;
        private boolean verifyCalled;
        private PluginRequestContext capturedRequestContext;
        private PaDataEntry capturedPaData;

        RecordingPreauth(boolean verifyResult) {
            this.verifyResult = verifyResult;
        }

        @Override
        public String getName() {
            return "recording-preauth";
        }

        @Override
        public int getVersion() {
            return 1;
        }

        @Override
        public PaDataType[] getPaTypes() {
            return new PaDataType[0];
        }

        @Override
        public void initWith(KdcContext context) {
        }

        @Override
        public PluginRequestContext initRequestContext(KdcRequest kdcRequest) {
            return null;
        }

        @Override
        public void provideEdata(KdcRequest kdcRequest, PluginRequestContext requestContext, PaData outPaData)
                throws KrbException {
        }

        @Override
        public boolean verify(KdcRequest kdcRequest, PluginRequestContext requestContext, PaDataEntry paData)
                throws KrbException {
            verifyCalled = true;
            capturedRequestContext = requestContext;
            capturedPaData = paData;
            return verifyResult;
        }

        @Override
        public void providePaData(KdcRequest kdcRequest, PluginRequestContext requestContext, PaData paData) {
        }

        @Override
        public PaFlags getFlags(KdcRequest kdcRequest, PluginRequestContext requestContext, PaDataType paType) {
            return null;
        }

        @Override
        public void destroy() {
        }
    }
}
