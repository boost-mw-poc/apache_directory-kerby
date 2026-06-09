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
package org.apache.kerby.kerberos.kdc.identitybackend;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class MySQLIdentityBackendRealmValidationTest {

    @Test
    public void testRealmValidationAllowsSafeRealm() throws KrbException {
        String normalized = MySQLIdentityBackend.normalizeAndValidateRealmForTableName("EXAMPLE.COM");
        assertThat(normalized).isEqualTo("example.com");
    }

    @Test
    public void testRealmValidationRejectsSqlInjectionPayload() {
        assertThatThrownBy(() -> MySQLIdentityBackend.normalizeAndValidateRealmForTableName("foo`; drop table x;--"))
            .isInstanceOf(KrbException.class)
            .hasMessageContaining("Invalid realm name");
    }

    @Test
    public void testRealmValidationRejectsTooLongRealm() {
        String tooLongRealm = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assertThatThrownBy(() -> MySQLIdentityBackend.normalizeAndValidateRealmForTableName(tooLongRealm))
            .isInstanceOf(KrbException.class)
            .hasMessageContaining("Invalid realm name");
    }
}
