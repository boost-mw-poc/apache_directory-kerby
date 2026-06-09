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
package org.apache.kerby.kerberos.kerb.server.preauth.token;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

public class TokenPreauthTest {

    @TempDir
    Path tempDir;

    @Test
    public void getKeyFileStreamShouldRequireExactFileNameMatchInDirectory() throws Exception {
        Path keyFile = tempDir.resolve("oauth2.com");
        Files.write(keyFile, "exact".getBytes(StandardCharsets.UTF_8));

        TokenPreauth tokenPreauth = new TokenPreauth();

        try (InputStream keyInput = invokeGetKeyFileStream(tokenPreauth, tempDir.toString(), "oauth2.com")) {
            assertThat(new String(readBytes(keyInput), StandardCharsets.UTF_8)).isEqualTo("exact");
        }
    }

    @Test
    public void getKeyFileStreamShouldAcceptExplicitPublicKeyFileNameInDirectory() throws Exception {
        Path keyFile = tempDir.resolve("oauth2.com_public_key.pem");
        Files.write(keyFile, "substring".getBytes(StandardCharsets.UTF_8));

        TokenPreauth tokenPreauth = new TokenPreauth();

        try (InputStream keyInput = invokeGetKeyFileStream(tokenPreauth, tempDir.toString(), "oauth2.com")) {
            assertThat(new String(readBytes(keyInput), StandardCharsets.UTF_8)).isEqualTo("substring");
        }
    }

    private InputStream invokeGetKeyFileStream(TokenPreauth tokenPreauth, String path, String issuer)
            throws Exception {
        Method method = TokenPreauth.class.getDeclaredMethod("getKeyFileStream", String.class, String.class);
        method.setAccessible(true);
        try {
            return (InputStream) method.invoke(tokenPreauth, path, issuer);
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof Exception) {
                throw (Exception) e.getCause();
            }
            throw new RuntimeException(e.getCause());
        }
    }

    private byte[] readBytes(InputStream inputStream) throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            outputStream.write(buffer, 0, bytesRead);
        }
        return outputStream.toByteArray();
    }
}
