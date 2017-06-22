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

import com.google.common.collect.ImmutableSet;
import io.crate.action.FutureActionListener;
import io.crate.action.sql.SessionContext;
import io.crate.analyze.AnalyzedStatement;
import io.crate.analyze.user.Privilege;
import io.crate.exceptions.*;
import io.crate.metadata.UsersMetaData;
import io.crate.metadata.UsersPrivilegesMetaData;
import org.elasticsearch.cluster.ClusterChangedEvent;
import org.elasticsearch.cluster.ClusterStateListener;
import org.elasticsearch.cluster.metadata.MetaData;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.Nullable;

import java.util.Collection;
import java.util.EnumSet;
import java.util.Set;
import java.util.concurrent.CompletableFuture;


public class UserManagerService implements UserManager, ClusterStateListener {

    public static User CRATE_USER = new User("crate", EnumSet.of(User.Role.SUPERUSER), ImmutableSet.of());

    private static final PrivilegeValidator PERMISSION_VISITOR = new PrivilegeValidator();

    static {
        MetaData.registerPrototype(UsersMetaData.TYPE, UsersMetaData.PROTO);
        MetaData.registerPrototype(UsersPrivilegesMetaData.TYPE, UsersPrivilegesMetaData.PROTO);
    }

    private final TransportCreateUserAction transportCreateUserAction;
    private final TransportDropUserAction transportDropUserAction;
    private final TransportPrivilegesAction transportPrivilegesAction;
    private volatile Set<User> users = ImmutableSet.of(CRATE_USER);

    public UserManagerService(TransportCreateUserAction transportCreateUserAction,
                              TransportDropUserAction transportDropUserAction,
                              TransportPrivilegesAction transportPrivilegesAction,
                              ClusterService clusterService) {
        this.transportCreateUserAction = transportCreateUserAction;
        this.transportDropUserAction = transportDropUserAction;
        this.transportPrivilegesAction = transportPrivilegesAction;
        clusterService.add(this);
    }

    static Set<User> getUsers(@Nullable UsersMetaData metaData,
                              @Nullable UsersPrivilegesMetaData privilegesMetaData) {
        ImmutableSet.Builder<User> usersBuilder = new ImmutableSet.Builder<User>().add(CRATE_USER);
        if (metaData != null) {
            for (String userName : metaData.users()) {
                Set<Privilege> privileges = null;
                if (privilegesMetaData != null) {
                    privileges = privilegesMetaData.getUserPrivileges(userName);
                }
                usersBuilder.add(new User(userName, ImmutableSet.of(), privileges == null ? ImmutableSet.of() : privileges));
            }
        }
        return usersBuilder.build();
    }

    @Override
    public CompletableFuture<Long> createUser(String userName) {
        FutureActionListener<WriteUserResponse, Long> listener = new FutureActionListener<>(r -> 1L);
        transportCreateUserAction.execute(new CreateUserRequest(userName), listener);
        return listener;
    }

    @Override
    public CompletableFuture<Long> dropUser(String userName, boolean ifExists) {
        FutureActionListener<WriteUserResponse, Long> listener = new FutureActionListener<>(WriteUserResponse::affectedRows);
        transportDropUserAction.execute(new DropUserRequest(userName, ifExists), listener);
        return listener;
    }

    @Override
    public CompletableFuture<Long> applyPrivileges(Collection<String> userNames, Collection<Privilege> privileges) {
        FutureActionListener<PrivilegesResponse, Long> listener = new FutureActionListener<>(PrivilegesResponse::affectedRows);
        transportPrivilegesAction.execute(new PrivilegesRequest(userNames, privileges), listener);
        return listener;
    }

    public Iterable<User> users() {
        return users;
    }

    @Override
    public void ensureAuthorized(AnalyzedStatement analyzedStatement,
                                 SessionContext sessionContext) {
        PERMISSION_VISITOR.validate(analyzedStatement, new PrivilegeContext(sessionContext, this));
    }

    @Override
    public void clusterChanged(ClusterChangedEvent event) {
        if (!event.metaDataChanged()) {
            return;
        }
        MetaData metaData = event.state().metaData();
        users = getUsers(metaData.custom(UsersMetaData.TYPE), metaData.custom(UsersPrivilegesMetaData.TYPE));
    }


    @Nullable
    public User findUser(String userName) {
        for (User user: users()) {
            if (userName.equals(user.name())) {
                return user;
            }
        }
        return null;
    }

    @Override
    public void raiseMissingPrivilegeException(Privilege.Clazz clazz, @Nullable Privilege.Type type, String ident, @Nullable User user) throws PermissionDeniedException {
        if (null == user) {
            // this can occur when the hba setting is not there,
            // in this case there is no authentication and everyone
            // can access the cluster
            return;
        }
        if (null == type) {
            // when type is null, we check if the user has any privilege type
            if (user.hasAnyPrivilege(clazz, ident)) {
                return;
            } else {
                throw new PermissionDeniedException(user.name());
            }
        }

        if (!user.isSuperUser() && Privilege.Type.DCL.equals(type)) {
            throw new PermissionDeniedException(user.name(), type);
        }

        if (user.isSuperUser()) {
            return;
        } else if (!user.hasPrivilege(type, clazz, ident)) {
            throw new PermissionDeniedException(user.name(), type);
        }
    }

    @Override
    public void validateException(Throwable t, SessionContext sessionContext) {
        String schemaName;
        if (sessionContext.user() != null && sessionContext.user().isSuperUser()) {
            return;
        }
        if (t instanceof TableUnknownException) {
            String[] parts = ((TableUnknownException) t).getTableIdent().split("\\.");
            schemaName = parts.length > 1 ? parts[0] : sessionContext.defaultSchema();
            raiseMissingPrivilegeException(Privilege.Clazz.SCHEMA, null, schemaName, sessionContext.user());
        }
        if (t instanceof AnalyzerUnknownException) {
            raiseMissingPrivilegeException(Privilege.Clazz.CLUSTER, null, null, sessionContext.user());
        }
        if (t instanceof ColumnUnknownException) {
            raiseMissingPrivilegeException(Privilege.Clazz.TABLE, null, ((ColumnUnknownException) t).getTableIdent().toString(), sessionContext.user());
        }
        if (t instanceof SchemaUnknownException) {
            raiseMissingPrivilegeException(Privilege.Clazz.CLUSTER, null, null, sessionContext.user());
        }
        if (t instanceof RelationUnknownException) {
            if (((RelationUnknownException) t).qualifiedName().getParts().size() > 1) {
                schemaName = ((RelationUnknownException) t).qualifiedName().getParts().get(0);
            } else {
                schemaName = sessionContext.defaultSchema();
            }
            raiseMissingPrivilegeException(Privilege.Clazz.SCHEMA, null, schemaName, sessionContext.user());
        }
        if (t instanceof RepositoryUnknownException) {
            raiseMissingPrivilegeException(Privilege.Clazz.CLUSTER, null, null, sessionContext.user());
        }
        if (t instanceof SnapshotUnknownException) {
            raiseMissingPrivilegeException(Privilege.Clazz.CLUSTER, null, null, sessionContext.user());
        }
        if (t instanceof UserDefinedFunctionUnknownException) {
            raiseMissingPrivilegeException(Privilege.Clazz.SCHEMA, null, ((UserDefinedFunctionUnknownException) t).getSchema(), sessionContext.user());
        }
        if (t instanceof PartitionUnknownException) {
            raiseMissingPrivilegeException(Privilege.Clazz.SCHEMA, null, ((PartitionUnknownException) t).getTableIdent().schema(), sessionContext.user());
        }
        if (t instanceof TableAlreadyExistsException) {
            schemaName = ((TableAlreadyExistsException) t).getSchema() != null ? ((TableAlreadyExistsException) t).getSchema() : sessionContext.defaultSchema();
            raiseMissingPrivilegeException(Privilege.Clazz.SCHEMA, null, schemaName, sessionContext.user());
        }
        if (t instanceof PartitionUnknownException) {
            raiseMissingPrivilegeException(Privilege.Clazz.TABLE, null, ((PartitionUnknownException) t).getTableIdent().toString(), sessionContext.user());
        }
        if (t instanceof RepositoryAlreadyExistsException) {
            raiseMissingPrivilegeException(Privilege.Clazz.CLUSTER, null, null, sessionContext.user());
        }
        if (t instanceof SnapshotAlreadyExistsExeption) {
            raiseMissingPrivilegeException(Privilege.Clazz.CLUSTER, null, null, sessionContext.user());
        }
        if (t instanceof UserDefinedFunctionAlreadyExistsException) {
            raiseMissingPrivilegeException(Privilege.Clazz.SCHEMA, null, ((UserDefinedFunctionAlreadyExistsException) t).getSchema(), sessionContext.user());
        }
        if (t instanceof TableAliasSchemaException) {
            raiseMissingPrivilegeException(Privilege.Clazz.SCHEMA, null, ((TableAliasSchemaException) t).getSchema(), sessionContext.user());
        }
    }
}
