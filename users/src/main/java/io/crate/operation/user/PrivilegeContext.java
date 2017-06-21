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


import io.crate.action.sql.SessionContext;
import io.crate.exceptions.UnauthorizedException;
import org.elasticsearch.common.Nullable;

import java.util.Locale;

class PrivilegeContext {

    private final SessionContext sessionContext;
    private final UserManager userManager;

    PrivilegeContext(SessionContext sessionContext, UserManager userManager) {
        this.sessionContext = sessionContext;
        this.userManager = userManager;
    }

    public SessionContext sessionContext() {
        return sessionContext;
    }

    public UserManager userManager() {
        return userManager;
    }

    public boolean isSuperUser(@Nullable User user) {
        return user != null && user.roles().contains(User.Role.SUPERUSER);
    }

    public void throwUnauthorized(@Nullable User user) {
        String userName = user != null ? user.name() : null;
        throw new UnauthorizedException(
            String.format(Locale.ENGLISH, "User \"%s\" is not authorized to execute statement", userName));
    }
}
