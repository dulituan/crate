/*
 * Licensed to Crate under one or more contributor license agreements.
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.  Crate licenses this file
 * to you under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
 *
 * However, if you have executed another commercial license agreement
 * with Crate these terms will supersede the license and you may use the
 * software solely pursuant to the terms of the relevant commercial
 * agreement.
 */

package io.crate.operation.auth;

import io.crate.operation.user.User;
import io.crate.operation.user.UserLookup;
import io.crate.protocols.postgres.ConnectionProperties;

import javax.annotation.Nullable;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class ClientCertAuth implements AuthenticationMethod {

    static final String NAME = "cert";
    private final UserLookup userLookup;

    ClientCertAuth(UserLookup userLookup) {
        this.userLookup = userLookup;
    }

    @Nullable
    @Override
    public User authenticate(String userName, ConnectionProperties connProperties) {
        Certificate clientCert = connProperties.clientCert();
        if (connProperties.hasSSL() && clientCert != null) {
            if (clientCert instanceof X509Certificate) {
                String CN = extractCN(((X509Certificate )clientCert).getSubjectX500Principal().getName());
                User user = lookupUser(userName, connProperties, CN);
                if (user != null) return user;
            }
        }
        throw new RuntimeException("Client certificate authentication failed for user \"" + userName + "\"");
    }

    @Nullable
    private User lookupUser(String userName, ConnectionProperties connProperties, String CN) {
        // userName is optional in HTTP;
        if (connProperties.protocol() == Protocol.HTTP) {
            if (userName == null || userName.equals("")) {
                userName = CN;
            }
        }
        if (userName.equals(CN)) {
            User user = userLookup.findUser(userName);
            if (user != null) {
                return user;
            }
        }
        return null;
    }

    private static String extractCN(String subjectDN) {
        /*
         * Get commonName using LdapName API
         * The DN of X509 certificates are in rfc2253 format. Ldap uses the same format.
         *
         * Doesn't use X500Name because it's internal API
         */
        try {
            LdapName ldapName = new LdapName(subjectDN);
            for (Rdn rdn : ldapName.getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    return rdn.getValue().toString();
                }
            }
            throw new RuntimeException("Could not extract commonName from client certificate subjectDN: " + subjectDN);
        } catch (InvalidNameException e) {
            throw new RuntimeException("Could not extract commonName from client certificate", e);
        }
    }

    @Override
    public String name() {
        return NAME;
    }
}
