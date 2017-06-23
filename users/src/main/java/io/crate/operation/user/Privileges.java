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

import com.google.common.annotations.VisibleForTesting;
import io.crate.action.sql.SessionContext;
import io.crate.analyze.user.Privilege;
import io.crate.exceptions.AnalyzerUnknownException;
import io.crate.exceptions.ColumnUnknownException;
import io.crate.exceptions.PartitionUnknownException;
import io.crate.exceptions.PermissionDeniedException;
import io.crate.exceptions.RelationUnknownException;
import io.crate.exceptions.RepositoryAlreadyExistsException;
import io.crate.exceptions.RepositoryUnknownException;
import io.crate.exceptions.SchemaUnknownException;
import io.crate.exceptions.SnapshotAlreadyExistsExeption;
import io.crate.exceptions.SnapshotUnknownException;
import io.crate.exceptions.TableAliasSchemaException;
import io.crate.exceptions.TableAlreadyExistsException;
import io.crate.exceptions.TableUnknownException;
import io.crate.exceptions.UserDefinedFunctionAlreadyExistsException;
import io.crate.exceptions.UserDefinedFunctionUnknownException;

class Privileges {

    /**
     * Checks if the user the concrete privilege for the given class and ident, if not raise exception.
     */
    static void raiseMissingPrivilegeException(Privilege.Type type,
                                               Privilege.Clazz clazz,
                                               String ident,
                                               User user) throws PermissionDeniedException {
        assert user != null : "User must not be null when trying to validate privileges";
        assert type != null : "Privilege type must not be null";

        if (user.hasPrivilege(type, clazz, ident) == false) {
            throw new PermissionDeniedException(user.name(), type);
        }
    }

    /**
     * Checks if the user has ANY privilege for the given class and ident, if not raise exception.
     */
    @VisibleForTesting
    static void raiseMissingPrivilegeException(Privilege.Clazz clazz,
                                               String ident,
                                               User user) throws PermissionDeniedException {
        assert user != null : "User must not be null when trying to validate privileges";
        if (user.hasAnyPrivilege(clazz, ident) == false) {
            throw new PermissionDeniedException(user.name());
        }
    }

    static void validateException(Throwable t, SessionContext sessionContext) {
        User user = sessionContext.user();
        if (user == null) {
            // this can occur when the hba setting is not there,
            // in this case there is no authentication and everyone
            // can access the cluster
            return;
        }

        if (user.isSuperUser()) {
            return;
        }
        if (t instanceof TableUnknownException) {
            String[] parts = ((TableUnknownException) t).getTableIdent().split("\\.");
            String schemaName = parts.length > 1 ? parts[0] : sessionContext.defaultSchema();
            raiseMissingPrivilegeException(Privilege.Clazz.SCHEMA, schemaName, user);
        }
        if (t instanceof AnalyzerUnknownException) {
            raiseMissingPrivilegeException(Privilege.Clazz.CLUSTER, null, user);
        }
        if (t instanceof ColumnUnknownException) {
            raiseMissingPrivilegeException(Privilege.Clazz.TABLE, ((ColumnUnknownException) t).getTableIdent().toString(), user);
        }
        if (t instanceof SchemaUnknownException) {
            raiseMissingPrivilegeException(Privilege.Clazz.CLUSTER, null, user);
        }
        if (t instanceof RelationUnknownException) {
            String schemaName;
            if (((RelationUnknownException) t).qualifiedName().getParts().size() > 1) {
                schemaName = ((RelationUnknownException) t).qualifiedName().getParts().get(0);
            } else {
                schemaName = sessionContext.defaultSchema();
            }
            raiseMissingPrivilegeException(Privilege.Clazz.SCHEMA, schemaName, user);
        }
        if (t instanceof RepositoryUnknownException) {
            raiseMissingPrivilegeException(Privilege.Clazz.CLUSTER, null, user);
        }
        if (t instanceof SnapshotUnknownException) {
            raiseMissingPrivilegeException(Privilege.Clazz.CLUSTER, null, user);
        }
        if (t instanceof UserDefinedFunctionUnknownException) {
            raiseMissingPrivilegeException(Privilege.Clazz.SCHEMA, ((UserDefinedFunctionUnknownException) t).getSchema(), user);
        }
        if (t instanceof PartitionUnknownException) {
            raiseMissingPrivilegeException(Privilege.Clazz.SCHEMA, ((PartitionUnknownException) t).getTableIdent().schema(), user);
        }
        if (t instanceof TableAlreadyExistsException) {
            String schemaName = ((TableAlreadyExistsException) t).getSchema() !=
                                null ? ((TableAlreadyExistsException) t).getSchema() : sessionContext.defaultSchema();
            raiseMissingPrivilegeException(Privilege.Clazz.SCHEMA, schemaName, user);
        }
        if (t instanceof PartitionUnknownException) {
            raiseMissingPrivilegeException(Privilege.Clazz.TABLE, ((PartitionUnknownException) t).getTableIdent().toString(), user);
        }
        if (t instanceof RepositoryAlreadyExistsException) {
            raiseMissingPrivilegeException(Privilege.Clazz.CLUSTER, null, user);
        }
        if (t instanceof SnapshotAlreadyExistsExeption) {
            raiseMissingPrivilegeException(Privilege.Clazz.CLUSTER, null, user);
        }
        if (t instanceof UserDefinedFunctionAlreadyExistsException) {
            raiseMissingPrivilegeException(Privilege.Clazz.SCHEMA, ((UserDefinedFunctionAlreadyExistsException) t).getSchema(), user);
        }
        if (t instanceof TableAliasSchemaException) {
            raiseMissingPrivilegeException(Privilege.Clazz.SCHEMA, ((TableAliasSchemaException) t).getSchema(), user);
        }
    }

}
