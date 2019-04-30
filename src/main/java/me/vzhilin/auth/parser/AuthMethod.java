package me.vzhilin.auth.parser;

/**
 * Поддерживаемые методы аутентификации
 */
public enum AuthMethod {
    /** Basic */
    BASIC("Basic"),

    /** Digest */
    DIGEST("Digest");

    private final String name;

    /**
     * Методы аутентификации
     * @param name имя
     */
    AuthMethod(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
