package io.crate.sql.tree;

import java.util.EnumSet;
import java.util.List;
import java.util.Objects;

public class GrantPrivilege extends Statement {

    private final EnumSet<Privilege> privileges;
    private final List<String> userNames;

    public GrantPrivilege(List<String> userNames, EnumSet<Privilege> privileges) {
        this.privileges = privileges;
        this.userNames = userNames;
    }

    public EnumSet<Privilege> privileges() {
        return privileges;
    }

    public List<String> userNames() {
        return userNames;
    }

    @Override
    public <R, C> R accept(AstVisitor<R, C> visitor, C context) {
        return visitor.visitGrantPrivilege(this, context);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        final GrantPrivilege that = (GrantPrivilege) o;
        return Objects.equals(this.privileges, that.privileges)
            && Objects.equals(this.userNames, that.userNames);
    }

    @Override
    public int hashCode() {
        return Objects.hash(privileges, userNames);
    }

    @Override
    public String toString() {
        return "GrantPrivilege{" +
            "privileges=" + privileges +
            ", userNames=" + userNames +
            '}';
    }
}
