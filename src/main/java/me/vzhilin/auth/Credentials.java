package me.vzhilin.auth;

import java.util.Objects;

public final class Credentials {
    public final String user;
    public final String password;

    public Credentials(String user, String password) {
        this.user = user;
        this.password = password;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Credentials that = (Credentials) o;
        return user.equals(that.user) &&
                password.equals(that.password);
    }

    @Override
    public int hashCode() {
        return Objects.hash(user, password);
    }
}
