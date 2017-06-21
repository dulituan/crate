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


import io.crate.analyze.*;
import io.crate.analyze.relations.*;
import io.crate.analyze.user.Privilege;
import io.crate.sql.tree.SetStatement;

import java.util.Locale;

class PrivilegeValidator {

    private final PrivilegeStatementVisitor privilegeStatementVisitor = new PrivilegeStatementVisitor();

    public Boolean validate(AnalyzedStatement analyzedStatement, PrivilegeContext context) {
        return privilegeStatementVisitor.process(analyzedStatement, context);
    }

    private final static class PrivilegeStatementVisitor extends AnalyzedStatementVisitor<PrivilegeContext, Boolean> {

        private final PrivilegeRelationVisitor privilegeRelationVisitor = new PrivilegeRelationVisitor();

        @Override
        protected Boolean visitAnalyzedStatement(AnalyzedStatement analyzedStatement, PrivilegeContext context) {
            throw new UnsupportedOperationException(String.format(Locale.ENGLISH, "Can't handle \"%s\"", analyzedStatement));
        }

        @Override
        protected Boolean visitCreateUserStatement(CreateUserAnalyzedStatement analysis, PrivilegeContext context) {
            if (!context.isSuperUser(context.sessionContext().user())) {
                context.throwUnauthorized(context.sessionContext().user());
            }
            return true;
        }

        @Override
        protected Boolean visitDropUserStatement(DropUserAnalyzedStatement analysis, PrivilegeContext context) {
            if (!context.isSuperUser(context.sessionContext().user())) {
                context.throwUnauthorized(context.sessionContext().user());
            }
            return true;
        }

        @Override
        public Boolean visitPrivilegesStatement(PrivilegesAnalyzedStatement analysis, PrivilegeContext context) {
            if (!context.isSuperUser(context.sessionContext().user())) {
                context.throwUnauthorized(context.sessionContext().user());
            }
            return true;
        }

        @Override
        public Boolean visitAlterTableStatement(AlterTableAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.TABLE,
                Privilege.Type.DDL,
                analysis.table().ident().toString(),
                context.sessionContext().user());
            return true;
        }

        @Override
        protected Boolean visitCopyFromStatement(CopyFromAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.TABLE,
                Privilege.Type.DML,
                analysis.table().ident().toString(),
                context.sessionContext().user());
            return true;
        }

        @Override
        protected Boolean visitCopyToStatement(CopyToAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.TABLE,
                Privilege.Type.DQL,
                analysis.subQueryRelation().tableRelation().getQualifiedName().toString(),
                context.sessionContext().user());
            return true;
        }

        @Override
        protected Boolean visitCreateTableStatement(CreateTableAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.TABLE,
                Privilege.Type.DDL,
                analysis.tableIdent().toString(),
                context.sessionContext().user());
            return true;
        }

        @Override
        protected Boolean visitCreateRepositoryAnalyzedStatement(CreateRepositoryAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.CLUSTER,
                Privilege.Type.DDL,
                null,
                context.sessionContext().user());
            return true;
        }

        @Override
        protected Boolean visitDeleteStatement(DeleteAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.TABLE,
                Privilege.Type.DML,
                analysis.analyzedRelation().tableInfo().ident().toString(),
                context.sessionContext().user());
            return true;
        }

        @Override
        protected Boolean visitInsertFromValuesStatement(InsertFromValuesAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.TABLE,
                Privilege.Type.DML,
                analysis.tableInfo().ident().toString(),
                context.sessionContext().user());
            return true;
        }

        @Override
        protected Boolean visitInsertFromSubQueryStatement(InsertFromSubQueryAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.TABLE,
                Privilege.Type.DML,
                analysis.tableInfo().ident().toString(),
                context.sessionContext().user());
            privilegeRelationVisitor.process(analysis.subQueryRelation(), context);
            return true;
        }

        @Override
        protected Boolean visitSelectStatement(SelectAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.TABLE,
                Privilege.Type.DQL,
                analysis.relation().getQualifiedName().toString(),
                context.sessionContext().user());
            privilegeRelationVisitor.process(analysis.relation(), context);
            return true;
        }

        @Override
        protected Boolean visitUpdateStatement(UpdateAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.TABLE,
                Privilege.Type.DML,
                analysis.sourceRelation().getQualifiedName().toString(),
                context.sessionContext().user());
            return true;
        }

        @Override
        protected Boolean visitCreateFunctionStatement(CreateFunctionAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.SCHEMA,
                Privilege.Type.DDL,
                analysis.schema(),
                context.sessionContext().user());
            return true;
        }

        @Override
        public Boolean visitDropFunctionStatement(DropFunctionAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.SCHEMA,
                Privilege.Type.DDL,
                analysis.schema(),
                context.sessionContext().user());
            return true;
        }

        @Override
        protected Boolean visitDropTableStatement(DropTableAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.TABLE,
                Privilege.Type.DDL,
                analysis.tableIdent().toString(),
                context.sessionContext().user());
            return true;
        }

        @Override
        protected Boolean visitCreateAnalyzerStatement(CreateAnalyzerAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.CLUSTER,
                Privilege.Type.DDL,
                null,
                context.sessionContext().user());
            return true;
        }

        @Override
        public Boolean visitCreateBlobTableStatement(CreateBlobTableAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.TABLE,
                Privilege.Type.DDL,
                analysis.tableIdent().toString(),
                context.sessionContext().user());
            return true;
        }

        @Override
        public Boolean visitDropBlobTableStatement(DropBlobTableAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.TABLE,
                Privilege.Type.DDL,
                analysis.tableIdent().toString(),
                context.sessionContext().user());
            return true;
        }

        @Override
        public Boolean visitOptimizeTableStatement(OptimizeTableAnalyzedStatement analysis, PrivilegeContext context) {
            if (!context.isSuperUser(context.sessionContext().user())) {
                context.throwUnauthorized(context.sessionContext().user());
            }
            return true;
        }

        @Override
        public Boolean visitRefreshTableStatement(RefreshTableAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.CLUSTER,
                Privilege.Type.DQL,
                null,
                context.sessionContext().user());
            return true;
        }

        @Override
        public Boolean visitAlterTableRenameStatement(AlterTableRenameAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.CLUSTER,
                Privilege.Type.DDL,
                analysis.targetTableIdent().toString(),
                context.sessionContext().user());
            return true;
        }

        @Override
        public Boolean visitAlterBlobTableStatement(AlterBlobTableAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.CLUSTER,
                Privilege.Type.DDL,
                analysis.table().ident().toString(),
                context.sessionContext().user());
            return true;
        }

        @Override
        public Boolean visitSetStatement(SetAnalyzedStatement analysis, PrivilegeContext context) {
            if (analysis.scope().equals(SetStatement.Scope.GLOBAL)) {
                if (!context.isSuperUser(context.sessionContext().user())) {
                    context.throwUnauthorized(context.sessionContext().user());
                }
            } else {
                context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.CLUSTER,
                    Privilege.Type.DQL,
                    null,
                    context.sessionContext().user());
            }
            return true;
        }

        @Override
        public Boolean visitAddColumnStatement(AddColumnAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.TABLE,
                Privilege.Type.DDL,
                analysis.table().ident().toString(),
                context.sessionContext().user());
            return true;
        }

        @Override
        public Boolean visitAlterTableOpenCloseStatement(AlterTableOpenCloseAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.TABLE,
                Privilege.Type.DDL,
                analysis.tableInfo().ident().toString(),
                context.sessionContext().user());
            return true;
        }

        @Override
        public Boolean visitKillAnalyzedStatement(KillAnalyzedStatement analysis, PrivilegeContext context) {
            if (!context.isSuperUser(context.sessionContext().user())) {
                context.throwUnauthorized(context.sessionContext().user());
            }
            return true;
        }

        @Override
        public Boolean visitShowCreateTableAnalyzedStatement(ShowCreateTableAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.TABLE,
                Privilege.Type.DQL,
                analysis.tableInfo().ident().toString(),
                context.sessionContext().user());
            return true;
        }

        @Override
        public Boolean visitDropRepositoryAnalyzedStatement(DropRepositoryAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.CLUSTER,
                Privilege.Type.DDL,
                null,
                context.sessionContext().user());
            return true;
        }

        @Override
        public Boolean visitDropSnapshotAnalyzedStatement(DropSnapshotAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.CLUSTER,
                Privilege.Type.DDL,
                null,
                context.sessionContext().user());
            return true;
        }

        @Override
        public Boolean visitCreateSnapshotAnalyzedStatement(CreateSnapshotAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.CLUSTER,
                Privilege.Type.DDL,
                null,
                context.sessionContext().user());
            return true;
        }

        @Override
        public Boolean visitRestoreSnapshotAnalyzedStatement(RestoreSnapshotAnalyzedStatement analysis, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.CLUSTER,
                Privilege.Type.DDL,
                null,
                context.sessionContext().user());
            return true;
        }

        @Override
        public Boolean visitResetAnalyzedStatement(ResetAnalyzedStatement resetAnalyzedStatement, PrivilegeContext context) {
            if (!context.isSuperUser(context.sessionContext().user())) {
                context.throwUnauthorized(context.sessionContext().user());
            }
            return true;
        }

        @Override
        public Boolean visitExplainStatement(ExplainAnalyzedStatement explainAnalyzedStatement, PrivilegeContext context) {
            return process(explainAnalyzedStatement.statement(), context);
        }

        @Override
        public Boolean visitBegin(AnalyzedBegin analyzedBegin, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.SCHEMA,
                Privilege.Type.DQL,
                null,
                context.sessionContext().user());
            return true;
        }
    }

    private final static class PrivilegeRelationVisitor extends AnalyzedRelationVisitor<PrivilegeContext, Boolean> {

        @Override
        protected Boolean visitAnalyzedRelation(AnalyzedRelation relation, PrivilegeContext context) {
            throw new UnsupportedOperationException(String.format(Locale.ENGLISH, "Can't handle \"%s\"", relation));
        }

        @Override
        public Boolean visitQueriedTable(QueriedTable table, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.TABLE,
                Privilege.Type.DQL,
                table.tableRelation().getQualifiedName().toString(),
                context.sessionContext().user());
            return true;
        }

        @Override
        public Boolean visitQueriedDocTable(QueriedDocTable table, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.TABLE,
                Privilege.Type.DQL,
                table.tableRelation().getQualifiedName().toString(),
                context.sessionContext().user());
            return true;
        }

        @Override
        public Boolean visitMultiSourceSelect(MultiSourceSelect multiSourceSelect, PrivilegeContext context) {
            for (AnalyzedRelation relation : multiSourceSelect.sources().values()) {
                process(relation, context);
            }
            return true;
        }

        @Override
        public Boolean visitTableRelation(TableRelation tableRelation, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.TABLE,
                Privilege.Type.DQL,
                tableRelation.getQualifiedName().toString(),
                context.sessionContext().user());
            return true;
        }

        @Override
        public Boolean visitDocTableRelation(DocTableRelation relation, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.TABLE,
                Privilege.Type.DQL,
                relation.getQualifiedName().toString(),
                context.sessionContext().user());
            return true;
        }

        @Override
        public Boolean visitExplain(ExplainAnalyzedStatement explainAnalyzedStatement, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.TABLE,
                Privilege.Type.DQL,
                explainAnalyzedStatement.getQualifiedName().toString(),
                context.sessionContext().user());
            return true;
        }

        @Override
        public Boolean visitTableFunctionRelation(TableFunctionRelation tableFunctionRelation, PrivilegeContext context) {
            context.userManager().raiseMissingPrivilegeException(Privilege.Clazz.TABLE,
                Privilege.Type.DQL,
                tableFunctionRelation.tableInfo().ident().toString(),
                context.sessionContext().user());
            return true;
        }

        @Override
        public Boolean visitQueriedSelectRelation(QueriedSelectRelation relation, PrivilegeContext context) {
            return process(relation.subRelation(), context);
        }
    }
}
