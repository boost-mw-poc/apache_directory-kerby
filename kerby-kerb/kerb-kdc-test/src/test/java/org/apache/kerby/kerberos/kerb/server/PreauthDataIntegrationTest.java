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
package org.apache.kerby.kerberos.kerb.server;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.client.ClientUtil;
import org.apache.kerby.kerberos.kerb.client.KrbContext;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.client.KrbSetting;
import org.apache.kerby.kerberos.kerb.client.request.AsRequestWithPasswd;
import org.apache.kerby.kerberos.kerb.transport.KrbNetwork;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;
import org.apache.kerby.kerberos.kerb.transport.TransportPair;
import org.apache.kerby.kerberos.kerb.type.base.KrbError;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessage;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessageType;
import org.apache.kerby.kerberos.kerb.type.kdc.AsReq;
import org.apache.kerby.kerberos.kerb.type.pa.PaData;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class PreauthDataIntegrationTest extends KdcTestBase {

    @Test
    public void unsupportedPreauthDataShouldBeRejectedWhenPreauthRequired() throws Exception {
        KrbMessage response = sendAsReqWithUnsupportedPreauthData();

        assertThat(response.getMsgType()).isEqualTo(KrbMessageType.KRB_ERROR);
        KrbError error = (KrbError) response;
        assertThat(error.getErrorCode()).isEqualTo(KrbErrorCode.KDC_ERR_PREAUTH_REQUIRED);
    }

    @Test
    public void validPreauthDataShouldBeAccepted() throws Exception {
        TgtTicket tgtTicket = getKrbClient().requestTgt(getClientPrincipal(), getClientPassword());
        assertThat(tgtTicket).isNotNull();
    }

    private KrbMessage sendAsReqWithUnsupportedPreauthData() throws Exception {
        KrbSetting setting = getKrbClient().getSetting();

        KrbContext context = new KrbContext();
        context.init(setting);

        AsRequestWithPasswd request = new AsRequestWithPasswd(context);
        request.setClientPrincipal(new org.apache.kerby.kerberos.kerb.type.base.PrincipalName(getClientPrincipal()));

        KOptions requestOptions = new KOptions();
        requestOptions.add(KrbOption.CLIENT_PRINCIPAL, getClientPrincipal());
        requestOptions.add(KrbOption.USE_PASSWD, true);
        requestOptions.add(KrbOption.USER_PASSWD, getClientPassword());
        request.setRequestOptions(requestOptions);
        request.process();

        AsReq asReq = (AsReq) request.getKdcReq();
        PaData unsupportedPaData = new PaData();
        unsupportedPaData.addElement(new PaDataEntry(PaDataType.PAC_REQUEST, new byte[] {1}));
        asReq.setPaData(unsupportedPaData);

        List<String> kdcList = ClientUtil.getKDCList(setting.getKdcRealm(), setting);
        TransportPair transportPair = ClientUtil.getTransportPair(setting, kdcList.get(0));

        KrbNetwork network = new KrbNetwork();
        network.setSocketTimeout(setting.getTimeout());
        KrbTransport transport = network.connect(transportPair);

        try {
            int bodyLength = asReq.encodingLength();
            ByteBuffer requestMessage;
            if (transport.isTcp()) {
                requestMessage = ByteBuffer.allocate(bodyLength + 4);
                requestMessage.putInt(bodyLength);
            } else {
                requestMessage = ByteBuffer.allocate(bodyLength);
            }
            KrbCodec.encode(asReq, requestMessage);
            transport.sendMessage(requestMessage);

            ByteBuffer responseMessage = transport.receiveMessage();
            return KrbCodec.decodeMessage(responseMessage);
        } finally {
            transport.release();
        }
    }
}
