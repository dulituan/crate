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
import io.crate.analyze.AddColumnAnalyzedStatement;
import io.crate.analyze.AlterBlobTableAnalyzedStatement;
import io.crate.analyze.AlterTableAnalyzedStatement;
import io.crate.analyze.AlterTableOpenCloseAnalyzedStatement;
import io.crate.analyze.AlterTableRenameAnalyzedStatement;
import io.crate.analyze.AnalyzedBegin;
import io.crate.analyze.AnalyzedStatement;
import io.crate.analyze.AnalyzedStatementVisitor;
import io.crate.analyze.CopyFromAnalyzedStatement;
import io.crate.analyze.CopyToAnalyzedStatement;
import io.crate.analyze.CreateAnalyzerAnalyzedStatement;
import io.crate.analyze.CreateBlobTableAnalyzedStatement;
import io.crate.analyze.CreateFunctionAnalyzedStatement;
import io.crate.analyze.CreateRepositoryAnalyzedStatement;
import io.crate.analyze.CreateSnapshotAnalyzedStatement;
import io.crate.analyze.CreateTableAnalyzedStatement;
import io.crate.analyze.CreateUserAnalyzedStatement;
import io.crate.analyze.DeleteAnalyzedStatement;
import io.crate.analyze.DropBlobTableAnalyzedStatement;
import io.crate.analyze.DropFunctionAnalyzedStatement;
import io.crate.analyze.DropRepositoryAnalyzedStatement;
import io.crate.analyze.DropSnapshotAnalyzedStatement;
import io.crate.analyze.DropTableAnalyzedStatement;
import io.crate.analyze.DropUserAnalyzedStatement;
import io.crate.analyze.ExplainAnalyzedStatement;
import io.crate.analyze.InsertFromSubQueryAnalyzedStatement;
import io.crate.analyze.InsertFromValuesAnalyzedStatement;
import io.crate.analyze.KillAnalyzedStatement;
import io.crate.analyze.MultiSourceSelect;
import io.crate.analyze.OptimizeTableAnalyzedStatement;
import io.crate.analyze.PrivilegesAnalyzedStatement;
import io.crate.analyze.QueriedSelectRelation;
import io.crate.analyze.QueriedTable;
import io.crate.analyze.RefreshTableAnalyzedStatement;
import io.crate.analyze.ResetAnalyzedStatement;
import io.crate.analyze.RestoreSnapshotAnalyzedStatement;
import io.crate.analyze.SelectAnalyzedStatement;
import io.crate.analyze.SetAnalyzedStatement;
import io.crate.analyze.ShowCreateTableAnalyzedStatement;
import io.crate.analyze.UpdateAnalyzedStatement;
import io.crate.analyze.relations.AnalyzedRelation;
import io.crate.analyze.relations.AnalyzedRelationVisitor;
import io.crate.analyze.relations.DocTableRelation;
import io.crate.analyze.relations.QueriedDocTable;
import io.crate.analyze.relations.TableFunctionRelation;
import io.crate.analyze.relations.TableRelation;
import io.crate.analyze.user.Privilege;
import io.crate.exceptions.UnauthorizedException;
import io.crate.metadata.PartitionName;
import io.crate.metadata.TableIdent;
import io.crate.sql.tree.SetStatement;
import org.elasticsearch.common.Nullable;

import java.util.Locale;

class PrivilegeValidator {

    private static final StatementVisitor VISITOR = new StatementVisitor();

    /**
     * Validates if the user has privileges for executing the given statement
     */
    void validate(AnalyzedStatement analyzedStatement, SessionContext sessionContext) {
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
        VISITOR.process(analyzedStatement, new Context(sessionContext, this));
    }

    private static class Context {

        private final SessionContext sessionContext;
        private final PrivilegeValidator validator;
        private Privilege.Type type;

        Context(SessionContext sessionContext, PrivilegeValidator validator) {
            this.sessionContext = sessionContext;
            this.validator = validator;
        }
    }

    private final static class StatementVisitor extends AnalyzedStatementVisitor<Context, Void> {

        private static final RelationVisitor RELATION_VISITOR = new RelationVisitor();

        private static void throwUnauthorized(@Nullable User user) {
            String userName = user != null ? user.name() : null;
            throw new UnauthorizedException(
                String.format(Locale.ENGLISH, "User \"%s\" is not authorized to execute statement", userName));
        }

        private void visitRelation(AnalyzedRelation relation, Context context) {
            assert context.type != null : "reuqired privilege type must be while validating relations";
            RELATION_VISITOR.process(relation, context);
        }


        @Override
        protected Void visitAnalyzedStatement(AnalyzedStatement analyzedStatement, Context context) {
            throw new UnsupportedOperationException(String.format(Locale.ENGLISH, "Can't handle \"%s\"", analyzedStatement));
        }

        @Override
        protected Void visitCreateUserStatement(CreateUserAnalyzedStatement analysis, Context context) {
            throwUnauthorized(context.sessionContext.user());
            return null;
        }

        @Override
        protected Void visitDropUserStatement(DropUserAnalyzedStatement analysis, Context context) {
            throwUnauthorized(context.sessionContext.user());
            return null;
        }

        @Override
        public Void visitPrivilegesStatement(PrivilegesAnalyzedStatement analysis, Context context) {
            throwUnauthorized(context.sessionContext.user());
            return null;
        }

        @Override
        public Void visitAlterTableStatement(AlterTableAnalyzedStatement analysis, Context context) {
            Privileges.raiseMissingPrivilegeException(
                Privilege.Type.DDL,
                Privilege.Clazz.TABLE,
                analysis.table().ident().toString(),
                context.sessionContext.user());
            return null;
        }

        @Override
        protected Void visitCopyFromStatement(CopyFromAnalyzedStatement analysis, Context context) {
            Privileges.raiseMissingPrivilegeException(
                Privilege.Type.DML,
                Privilege.Clazz.TABLE,
                analysis.table().ident().toString(),
                context.sessionContext.user());
            return null;
        }

        @Override
        protected Void visitCopyToStatement(CopyToAnalyzedStatement analysis, Context context) {
            context.type = Privilege.Type.DQL;
            visitRelation(analysis.subQueryRelation(), context);
            return null;
        }

        @Override
        protected Void visitCreateTableStatement(CreateTableAnalyzedStatement analysis, Context context) {
            Privileges.raiseMissingPrivilegeException(
                Privilege.Type.DDL,
                Privilege.Clazz.SCHEMA,
                analysis.tableIdent().schema(),
                context.sessionContext.user());
            return null;
        }

        @Override
        protected Void visitCreateRepositoryAnalyzedStatement(CreateRepositoryAnalyzedStatement analysis, Context context) {
            Privileges.raiseMissingPrivilegeException(
                Privilege.Type.DDL,
                Privilege.Clazz.CLUSTER,
                null,
                context.sessionContext.user());
            return null;
        }

        @Override
        protected Void visitDeleteStatement(DeleteAnalyzedStatement analysis, Context context) {
            context.type = Privilege.Type.DML;
            visitRelation(analysis.analyzedRelation(), context);
            return null;
        }

        @Override
        protected Void visitInsertFromValuesStatement(InsertFromValuesAnalyzedStatement analysis, Context context) {
            Privileges.raiseMissingPrivilegeException(
                Privilege.Type.DML,
                Privilege.Clazz.TABLE,
                analysis.tableInfo().ident().toString(),
                context.sessionContext.user());
            return null;
        }

        @Override
        protected Void visitInsertFromSubQueryStatement(InsertFromSubQueryAnalyzedStatement analysis, Context context) {
            Privileges.raiseMissingPrivilegeException(
                Privilege.Type.DML,
                Privilege.Clazz.TABLE,
                analysis.tableInfo().ident().toString(),
                context.sessionContext.user());
            context.type = Privilege.Type.DQL;
            visitRelation(analysis.subQueryRelation(), context);
            return null;
        }

        @Override
        protected Void visitSelectStatement(SelectAnalyzedStatement analysis, Context context) {
            context.type = Privilege.Type.DQL;
            visitRelation(analysis.relation(), context);
            return null;
        }

        @Override
        protected Void visitUpdateStatement(UpdateAnalyzedStatement analysis, Context context) {
            context.type = Privilege.Type.DML;
            visitRelation(analysis.sourceRelation(), context);
            return null;
        }

        @Override
        protected Void visitCreateFunctionStatement(CreateFunctionAnalyzedStatement analysis, Context context) {
            Privileges.raiseMissingPrivilegeException(
                Privilege.Type.DDL,
                Privilege.Clazz.SCHEMA,
                analysis.schema(),
                context.sessionContext.user());
            return null;
        }

        @Override
        public Void visitDropFunctionStatement(DropFunctionAnalyzedStatement analysis, Context context) {
            Privileges.raiseMissingPrivilegeException(
                Privilege.Type.DDL,
                Privilege.Clazz.SCHEMA,
                analysis.schema(),
                context.sessionContext.user());
            return null;
        }

        @Override
        protected Void visitDropTableStatement(DropTableAnalyzedStatement analysis, Context context) {
            Privileges.raiseMissingPrivilegeException(
                Privilege.Type.DDL,
                Privilege.Clazz.TABLE,
                analysis.tableIdent().toString(),
                context.sessionContext.user());
            return null;
        }

        @Override
        protected Void visitCreateAnalyzerStatement(CreateAnalyzerAnalyzedStatement analysis, Context context) {
            Privileges.raiseMissingPrivilegeException(
                Privilege.Type.DDL,
                Privilege.Clazz.CLUSTER,
                null,
                context.sessionContext.user());
            return null;
        }

        @Override
        public Void visitCreateBlobTableStatement(CreateBlobTableAnalyzedStatement analysis, Context context) {
            Privileges.raiseMissingPrivilegeException(
                Privilege.Type.DDL,
                Privilege.Clazz.SCHEMA,
                analysis.tableIdent().schema(),
                context.sessionContext.user());
            return null;
        }

        @Override
        public Void visitDropBlobTableStatement(DropBlobTableAnalyzedStatement analysis, Context context) {
            Privileges.raiseMissingPrivilegeException(
                Privilege.Type.DDL,
                Privilege.Clazz.TABLE,
                analysis.tableIdent().toString(),
                context.sessionContext.user());
            return null;
        }

        @Override
        public Void visitOptimizeTableStatement(OptimizeTableAnalyzedStatement analysis, Context context) {
            throwUnauthorized(context.sessionContext.user());
            return null;
        }

        @Override
        public Void visitRefreshTableStatement(RefreshTableAnalyzedStatement analysis, Context context) {
            for (String indexName : analysis.indexNames()) {
                String tableName;
                if (PartitionName.isPartition(indexName)) {
                    tableName = PartitionName.fromIndexOrTemplate(indexName).tableIdent().toString();
                } else {
                    tableName = TableIdent.fromIndexName(indexName).toString();
                }
                Privileges.raiseMissingPrivilegeException(
                    Privilege.Type.DQL,
                    Privilege.Clazz.TABLE,
                    tableName,
                    context.sessionContext.user());
            }
            return null;
        }

        @Override
        public Void visitAlterTableRenameStatement(AlterTableRenameAnalyzedStatement analysis, Context context) {
            Privileges.raiseMissingPrivilegeException(
                Privilege.Type.DDL,
                Privilege.Clazz.TABLE,
                analysis.sourceTableInfo().toString(),
                context.sessionContext.user());
            return null;
        }

        @Override
        public Void visitAlterBlobTableStatement(AlterBlobTableAnalyzedStatement analysis, Context context) {
            Privileges.raiseMissingPrivilegeException(
                Privilege.Type.DDL,
                Privilege.Clazz.TABLE,
                analysis.table().ident().toString(),
                context.sessionContext.user());
            return null;
        }

        @Override
        public Void visitSetStatement(SetAnalyzedStatement analysis, Context context) {
            if (analysis.scope().equals(SetStatement.Scope.GLOBAL)) {
                throwUnauthorized(context.sessionContext.user());
                return null;
            }
            Privileges.raiseMissingPrivilegeException(
                Privilege.Type.DQL,
                Privilege.Clazz.CLUSTER,
                null,
                context.sessionContext.user());
            return null;
        }

        @Override
        public Void visitAddColumnStatement(AddColumnAnalyzedStatement analysis, Context context) {
            Privileges.raiseMissingPrivilegeException(
                Privilege.Type.DDL,
                Privilege.Clazz.TABLE,
                analysis.table().ident().toString(),
                context.sessionContext.user());
            return null;
        }

        @Override
        public Void visitAlterTableOpenCloseStatement(AlterTableOpenCloseAnalyzedStatement analysis, Context context) {
            Privileges.raiseMissingPrivilegeException(
                Privilege.Type.DDL,
                Privilege.Clazz.TABLE,
                analysis.tableInfo().ident().toString(),
                context.sessionContext.user());
            return null;
        }

        @Override
        public Void visitKillAnalyzedStatement(KillAnalyzedStatement analysis, Context context) {
            throwUnauthorized(context.sessionContext.user());
            return null;
        }

        @Override
        public Void visitShowCreateTableAnalyzedStatement(ShowCreateTableAnalyzedStatement analysis, Context context) {
            Privileges.raiseMissingPrivilegeException(
                Privilege.Type.DQL,
                Privilege.Clazz.TABLE,
                analysis.tableInfo().ident().toString(),
                context.sessionContext.user());
            return null;
        }

        @Override
        public Void visitDropRepositoryAnalyzedStatement(DropRepositoryAnalyzedStatement analysis, Context context) {
            Privileges.raiseMissingPrivilegeException(
                Privilege.Type.DDL,
                Privilege.Clazz.CLUSTER,
                null,
                context.sessionContext.user());
            return null;
        }

        @Override
        public Void visitDropSnapshotAnalyzedStatement(DropSnapshotAnalyzedStatement analysis, Context context) {
            Privileges.raiseMissingPrivilegeException(
                Privilege.Type.DDL,
                Privilege.Clazz.CLUSTER,
                null,
                context.sessionContext.user());
            return null;
        }

        @Override
        public Void visitCreateSnapshotAnalyzedStatement(CreateSnapshotAnalyzedStatement analysis, Context context) {
            Privileges.raiseMissingPrivilegeException(
                Privilege.Type.DDL,
                Privilege.Clazz.CLUSTER,
                null,
                context.sessionContext.user());
            return null;
        }

        @Override
        public Void visitRestoreSnapshotAnalyzedStatement(RestoreSnapshotAnalyzedStatement analysis, Context context) {
            Privileges.raiseMissingPrivilegeException(
                Privilege.Type.DDL,
                Privilege.Clazz.CLUSTER,
                null,
                context.sessionContext.user());
            return null;
        }

        @Override
        public Void visitResetAnalyzedStatement(ResetAnalyzedStatement resetAnalyzedStatement, Context context) {
            throwUnauthorized(context.sessionContext.user());
            return null;
        }

        @Override
        public Void visitExplainStatement(ExplainAnalyzedStatement explainAnalyzedStatement, Context context) {
            return process(explainAnalyzedStatement.statement(), context);
        }

        @Override
        public Void visitBegin(AnalyzedBegin analyzedBegin, Context context) {
            Privileges.raiseMissingPrivilegeException(
                Privilege.Type.DQL,
                Privilege.Clazz.CLUSTER,
                null,
                context.sessionContext.user());
            return null;
        }
    }

    private final static class RelationVisitor extends AnalyzedRelationVisitor<Context, Void> {

        @Override
        protected Void visitAnalyzedRelation(AnalyzedRelation relation, Context context) {
            throw new UnsupportedOperationException(String.format(Locale.ENGLISH, "Can't handle \"%s\"", relation));
        }

        @Override
        public Void visitQueriedTable(QueriedTable table, Context context) {
            process(table.tableRelation(), context);
            return null;
        }

        @Override
        public Void visitQueriedDocTable(QueriedDocTable table, Context context) {
            Privileges.raiseMissingPrivilegeException(
                context.type,
                Privilege.Clazz.TABLE,
                table.tableRelation().getQualifiedName().toString(),
                context.sessionContext.user());
            return null;
        }

        @Override
        public Void visitMultiSourceSelect(MultiSourceSelect multiSourceSelect, Context context) {
            for (AnalyzedRelation relation : multiSourceSelect.sources().values()) {
                process(relation, context);
            }
            return null;
        }

        @Override
        public Void visitTableRelation(TableRelation tableRelation, Context context) {
            Privileges.raiseMissingPrivilegeException(
                context.type,
                Privilege.Clazz.TABLE,
                tableRelation.getQualifiedName().toString(),
                context.sessionContext.user());
            return null;
        }

        @Override
        public Void visitDocTableRelation(DocTableRelation relation, Context context) {
            Privileges.raiseMissingPrivilegeException(
                context.type,
                Privilege.Clazz.TABLE,
                relation.getQualifiedName().toString(),
                context.sessionContext.user());
            return null;
        }

        @Override
        public Void visitTableFunctionRelation(TableFunctionRelation tableFunctionRelation, Context context) {
            Privileges.raiseMissingPrivilegeException(
                context.type,
                Privilege.Clazz.TABLE,
                tableFunctionRelation.tableInfo().ident().toString(),
                context.sessionContext.user());
            return null;
        }

        @Override
        public Void visitQueriedSelectRelation(QueriedSelectRelation relation, Context context) {
            return process(relation.subRelation(), context);
        }
    }
}
