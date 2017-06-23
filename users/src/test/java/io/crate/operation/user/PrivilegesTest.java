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

package io.crate.operation.user;

import io.crate.action.sql.SessionContext;
import io.crate.analyze.user.Privilege;
import io.crate.exceptions.PermissionDeniedException;
import io.crate.exceptions.TableUnknownException;
import io.crate.metadata.TableIdent;
import io.crate.test.integration.CrateUnitTest;
import org.junit.Test;

import java.util.Collections;
import java.util.Properties;

import static io.crate.operation.user.UserManagerService.CRATE_USER;

public class PrivilegesTest extends CrateUnitTest {

    @Test
    public void testExceptionIsThrownIfUserHasNotRequiredPrivilege() throws Exception {
        User user = new User("ford", Collections.emptySet(), Collections.emptySet());

        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage("Missing 'DQL' Privilege for user 'ford'");
        Privileges.raiseMissingPrivilegeException(Privilege.Type.DQL, Privilege.Clazz.CLUSTER, null, user);
    }

    @Test
    public void testExceptionIsThrownIfUserHasNotAnyPrivilege() throws Exception {
        User user = new User("ford", Collections.emptySet(), Collections.emptySet());

        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage("Missing Privilege for user 'ford'");
        Privileges.raiseMissingPrivilegeException(Privilege.Clazz.CLUSTER, null, user);
    }

    @Test
    public void testValidateExceptionDoesNothingIfNoUser() throws Exception {
        // does not throw any exception
        Privileges.validateException(new TableUnknownException(TableIdent.fromIndexName("users")),
            new SessionContext(new Properties(), null));
    }

    @Test
    public void testValidateExceptionDoesNothingForSuperUsers() throws Exception {
        // does not throw any exception
        Privileges.validateException(new TableUnknownException(TableIdent.fromIndexName("users")),
            new SessionContext(new Properties(), CRATE_USER));
    }
}
