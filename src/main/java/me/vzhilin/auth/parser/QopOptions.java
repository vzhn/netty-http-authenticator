package me.vzhilin.auth.parser;

/** Quality of protection */
public enum QopOptions {
    /** Authentication */
    AUTH("auth"),

    /** Authentication with integrity protection */
    AUTH_INT("auth-int");

    private final String name;

    QopOptions(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
