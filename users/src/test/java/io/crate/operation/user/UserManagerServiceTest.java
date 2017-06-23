/*
 * This file is part of a module with proprietary Enterprise Features.
 *
 * Licensed to Crate.io Inc. ("Crate.io") under one or more contributor
 * license agreements.  See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited.
 *
 * To use this file, Crate.io must have given you permission to enable and
 * use such Enterprise Features and you must have a valid Enterprise or
 * Subscription Agreement with Crate.io.  If you enable or use the Enterprise
 * Features, you represent and warrant that you have a valid Enterprise or
 * Subscription Agreement with Crate.io.  Your use of the Enterprise Features
 * if governed by the terms and conditions of your Enterprise or Subscription
 * Agreement with Crate.io.
 */

package io.crate.operation.user;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import io.crate.action.sql.Option;
import io.crate.action.sql.SessionContext;
import io.crate.analyze.CreateUserAnalyzedStatement;
import io.crate.analyze.DropUserAnalyzedStatement;
import io.crate.exceptions.ResourceUnknownException;
import io.crate.exceptions.UnauthorizedException;
import io.crate.metadata.UsersMetaData;
import io.crate.metadata.UsersPrivilegesMetaData;
import io.crate.test.integration.CrateDummyClusterServiceUnitTest;
import org.junit.Before;
import org.junit.Test;

import java.util.Collections;
import java.util.Set;

import static io.crate.operation.user.UserManagerService.CRATE_USER;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;

public class UserManagerServiceTest extends CrateDummyClusterServiceUnitTest {

    private UserManagerService userManagerService;

    @Before
    public void setUpUserManager() throws Exception {
        userManagerService = new UserManagerService(null, null, null, clusterService);
    }

    @Test
    public void testNullAndEmptyMetaData() {
        // the users list will always contain a crate user
        Set<User> users = UserManagerService.getUsers(null, null);
        assertThat(users, contains(CRATE_USER));

        users = UserManagerService.getUsers(new UsersMetaData(), new UsersPrivilegesMetaData());
        assertThat(users, contains(CRATE_USER));
    }

    @Test
    public void testNewUser() {
        Set<User> users = UserManagerService.getUsers(new UsersMetaData(ImmutableList.of("arthur")), new UsersPrivilegesMetaData());
        assertThat(users, containsInAnyOrder(new User("arthur", ImmutableSet.of(), ImmutableSet.of()), CRATE_USER));
    }

    @Test
    public void testCreateUserStatementCheckPermissionFalse() {
        expectedException.expect(UnauthorizedException.class);
        expectedException.expectMessage(is("User \"noPriviligeUser\" is not authorized to execute statement"));
        userManagerService.ensureAuthorized(new CreateUserAnalyzedStatement(""),
            new SessionContext(0, Option.NONE, "my_schema", new User("noPriviligeUser",
                Collections.emptySet(),
                Collections.emptySet())));
    }

    @Test
    public void testCreateUserStatementCheckPermissionTrue() {
        userManagerService.ensureAuthorized(new CreateUserAnalyzedStatement("bla"),
            new SessionContext(0, Option.NONE, "my_schema", UserManagerService.CRATE_USER));
    }

    @Test
    public void testDropUserStatementCheckPermissionFalse() {
        expectedException.expect(UnauthorizedException.class);
        expectedException.expectMessage(is("User \"noPriviligeUser\" is not authorized to execute statement"));
        userManagerService.ensureAuthorized(new DropUserAnalyzedStatement("", false),
            new SessionContext(0, Option.NONE, "my_schema", new User("noPriviligeUser",
                Collections.emptySet(),
                Collections.emptySet())));
    }

    @Test
    public void testDropUserStatementCheckPermissionTrue() {
        userManagerService.ensureAuthorized(new DropUserAnalyzedStatement("bla", false),
            new SessionContext(0, Option.NONE, "my_schema", UserManagerService.CRATE_USER));
    }

    @Test
    public void testValidateExistingUserName() {
        // must not throw an exception, user is found
        UserManagerService.validateUsernames(Lists.newArrayList("ford"), s -> new User(s, Collections.emptySet(), Collections.emptySet()));
    }

    @Test
    public void testValidateNonExistingUserNameThrowsException() {
        expectedException.expect(ResourceUnknownException.class);
        expectedException.expectMessage("User 'ford' does not exists");
        UserManagerService.validateUsernames(Lists.newArrayList("ford"), s -> null);
    }

    @Test
    public void testValidateSuperUserThrowsException() {
        expectedException.expect(UnsupportedOperationException.class);
        expectedException.expectMessage("Cannot alter privileges for superuser 'crate'");
        UserManagerService.validateUsernames(Lists.newArrayList(CRATE_USER.name()), s -> CRATE_USER);
    }
}
