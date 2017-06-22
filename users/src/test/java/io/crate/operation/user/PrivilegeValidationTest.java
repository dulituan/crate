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
import io.crate.action.sql.Option;
import io.crate.action.sql.SessionContext;
import io.crate.analyze.ParameterContext;
import io.crate.analyze.TableDefinitions;
import io.crate.analyze.user.Privilege;
import io.crate.data.Row;
import io.crate.exceptions.PermissionDeniedException;
import io.crate.exceptions.UnauthorizedException;
import io.crate.metadata.TableIdent;
import io.crate.metadata.blob.BlobSchemaInfo;
import io.crate.sql.parser.SqlParser;
import io.crate.test.integration.CrateDummyClusterServiceUnitTest;
import io.crate.testing.SQLExecutor;
import org.junit.Before;
import org.junit.Test;

import java.util.Collections;

import static org.hamcrest.Matchers.is;

public class PrivilegeValidationTest extends CrateDummyClusterServiceUnitTest {

    private static final User crateUser = new User("crateUser",
        ImmutableSet.of(User.Role.SUPERUSER),
        Collections.EMPTY_SET);

    private static final User dmlUser = new User("dmlUser",
        Collections.EMPTY_SET,
        ImmutableSet.of(new Privilege(Privilege.State.GRANT, Privilege.Type.DML, Privilege.Clazz.CLUSTER, null, "dmlUser")));

    private static final User ddlUser = new User("ddlUser",
        Collections.EMPTY_SET,
        ImmutableSet.of(new Privilege(Privilege.State.GRANT, Privilege.Type.DDL, Privilege.Clazz.CLUSTER, null, "crate")));

    private static final User dqlUser = new User("dqlUser",
        Collections.EMPTY_SET,
        ImmutableSet.of(new Privilege(Privilege.State.GRANT, Privilege.Type.DQL, Privilege.Clazz.CLUSTER, null, "crate")));

    private static final User allUser = new User("allUser",
        Collections.EMPTY_SET,
        ImmutableSet.of(new Privilege(Privilege.State.GRANT, Privilege.Type.DQL, Privilege.Clazz.CLUSTER, null, "crate"),
            new Privilege(Privilege.State.GRANT, Privilege.Type.DML, Privilege.Clazz.CLUSTER, null, "crate"),
            new Privilege(Privilege.State.GRANT, Privilege.Type.DDL, Privilege.Clazz.CLUSTER, null, "crate")));

    private static final User noPriviligeUser = new User("noPriviligeUser",
        Collections.EMPTY_SET,
        Collections.EMPTY_SET);

    private SQLExecutor e;
    private UserManager userManager;

    @Before
    public void setUpSQLExecutor() throws Exception {
        userManager = new UserManagerService(null, null, null, clusterService);
        TableIdent myBlobsIdent = new TableIdent(BlobSchemaInfo.NAME, "blobs");
        e = SQLExecutor.builder(clusterService, () -> userManager)
            .addBlobTable(TableDefinitions.createBlobTable(myBlobsIdent, clusterService))
            .enableDefaultTables()
            .build();
    }

    @Test
    public void testDmlUserSelectStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing 'DQL' Privilege for user 'dmlUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("select * from sys.cluster"),
            new SessionContext(0, Option.NONE, "doc", dmlUser), null);
    }

    @Test
    public void testDmlUserMultiSelectStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing 'DQL' Privilege for user 'dmlUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("select * from (select id from sys.cluster) t1 where t1.id != null"),
            new SessionContext(0, Option.NONE, "doc", dmlUser), null);
    }

    @Test
    public void testDmlUserAlterTableStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing 'DDL' Privilege for user 'dmlUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("alter table users add column additional_pk string"),
            new SessionContext(0, Option.NONE, "doc", dmlUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testDqlUserCopyFromStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing 'DML' Privilege for user 'dqlUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("copy users from '/some/distant/file.ext'"),
            new SessionContext(0, Option.NONE, "doc", dqlUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeUserCopyToStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing 'DQL' Privilege for user 'noPriviligeUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("copy users to directory '/foo'"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeUserCreateTableStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing 'DDL' Privilege for user 'noPriviligeUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("create Table my_table(x long)"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeUserCreateRepositoryStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing 'DDL' Privilege for user 'noPriviligeUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("CREATE REPOSITORY \"new_repository\" TYPE \"fs\" with (location='/mount/backups/my_backup', compress=True)"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeUserDeleteStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing 'DML' Privilege for user 'noPriviligeUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("delete from users where name='Trillian'"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeUserInsertStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing 'DML' Privilege for user 'noPriviligeUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("insert into users (id, name) values (1, 'Trillian')"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeUserUpdateStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing 'DML' Privilege for user 'noPriviligeUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("update users set name='Ford Prefect'"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeUserCreateFunctionStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing 'DDL' Privilege for user 'noPriviligeUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("CREATE FUNCTION bar(long, long)" +
                " RETURNS long LANGUAGE dummy_lang AS 'function(a, b) { return a + b; }'"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeUserDropFunctionStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing 'DDL' Privilege for user 'noPriviligeUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("DROP FUNCTION bar(long, object)"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeUserDropTableStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing 'DDL' Privilege for user 'noPriviligeUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("DROP table users"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeCreateAnalyzerStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing 'DDL' Privilege for user 'noPriviligeUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("CREATE ANALYZER a1 (tokenizer lowercase)"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeCreateBlobTableStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing 'DDL' Privilege for user 'noPriviligeUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("create blob table screenshots"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeDropBlobTableStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing 'DDL' Privilege for user 'noPriviligeUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("drop blob table blobs"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeOptimizeTableStatementThrowsException() {
        expectedException.expect(UnauthorizedException.class);
        expectedException.expectMessage(is("User \"noPriviligeUser\" is not authorized to execute statement"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("OPTIMIZE TABLE users"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeRefreshTableStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing 'DQL' Privilege for user 'noPriviligeUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("refresh table parted"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeAlterBlobTableStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing 'DDL' Privilege for user 'noPriviligeUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("alter blob table blobs set (number_of_replicas=2)"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeSetGlobalStatementThrowsException() {
        expectedException.expect(UnauthorizedException.class);
        expectedException.expectMessage(is("User \"noPriviligeUser\" is not authorized to execute statement"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("SET GLOBAL PERSISTENT stats.operations_log_size=1"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeSetSessionStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing 'DQL' Privilege for user 'noPriviligeUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("SET SESSION something = 1,2,3"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeUserAlterTableAddColumnStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing 'DDL' Privilege for user 'noPriviligeUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("alter table users_clustered_by_only add column foobar string"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeUserKillAllStatementThrowsException() {
        expectedException.expect(UnauthorizedException.class);
        expectedException.expectMessage(is("User \"noPriviligeUser\" is not authorized to execute statement"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("kill all"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeUserShowStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing 'DQL' Privilege for user 'noPriviligeUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("show tables in QNAME"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeUserDropRepositoryStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing Privilege for user 'noPriviligeUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("DROP REPOSITORY \"unknown_repo\""),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeUserDropSnapshotStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing Privilege for user 'noPriviligeUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("drop snapshot my_repo.my_snap_1"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeUserCreateSnapshotStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing Privilege for user 'noPriviligeUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("CREATE SNAPSHOT my_repo.my_snapshot ALL WITH (wait_for_completion=true)"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeUserResetStatementThrowsException() {
        expectedException.expect(UnauthorizedException.class);
        expectedException.expectMessage(is("User \"noPriviligeUser\" is not authorized to execute statement"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("RESET GLOBAL stats"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeUserExplainStatementThrowsException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing 'DQL' Privilege for user 'noPriviligeUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("explain select id from sys.cluster"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeUserSelectUnknownSchemaThrowsPermissionDeniedException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing Privilege for user 'noPriviligeUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("select * from non_schema.t"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

    @Test
    public void testNoPriviligeUserTableAlreadyExistsThrowsPermissionDeniedException() {
        expectedException.expect(PermissionDeniedException.class);
        expectedException.expectMessage(is("Missing Privilege for user 'noPriviligeUser'"));
        e.analyzer.boundAnalyze(SqlParser.createStatement("create table users (i long )"),
            new SessionContext(0, Option.NONE, "doc", noPriviligeUser), new ParameterContext(Row.EMPTY, Collections.<Row>emptyList()));
    }

}


