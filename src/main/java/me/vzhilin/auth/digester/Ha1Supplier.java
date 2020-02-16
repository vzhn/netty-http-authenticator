package me.vzhilin.auth.digester;

import me.vzhilin.auth.parser.DigestAlgorithm;

public interface Ha1Supplier {
    Ha1 hash(DigestAlgorithm algorithm, String realm);
}
