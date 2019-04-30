/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 Vladimir Zhilin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package me.vzhilin.auth.parser;

/**
 * DigestAlgorithms
 */
public enum DigestAlgorithm {
    /** MD5 algorithm */
    MD5("MD5", false),

    /** MD5-sess algorithm */
    MD5_SESS("MD5-sess", true),

    /** SHA-512-256 algorithm */
    SHA_512_256("SHA-512-256", false),

    /** SHA-512-256-sess algorithm */
    SHA_512_256_SESS("SHA-512-256-sess", true),

    /** SHA-256 algorithm */
    SHA_256("SHA-256", false),

    /** SHA-256 algorithm */
    SHA_256_SESS("SHA-256-sess", true);

    private final boolean sess;
    private String name;

    DigestAlgorithm(String name, boolean sess) {
        this.name = name;
        this.sess = sess;
    }

    /**
     * @return true, if "sess"
     */
    public boolean isSess() {
        return sess;
    }

    @Override
    public String toString() {
        return name;
    }
}
