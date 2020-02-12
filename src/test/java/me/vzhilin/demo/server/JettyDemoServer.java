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
package me.vzhilin.demo.server;

import org.eclipse.jetty.security.*;
import org.eclipse.jetty.security.authentication.DigestAuthenticator;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;

import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.util.security.Constraint;
import org.eclipse.jetty.util.security.Credential;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JettyDemoServer {
    private final UserStore userStore = new UserStore();
    private final ConstraintSecurityHandler securityHandler = new ConstraintSecurityHandler();
    private Server server;

    public static void main(String... argv) throws Exception {
        final JettyDemoServer demoServer = new JettyDemoServer("Realm");
        demoServer.addUser("user", "pass", "role");
        demoServer.addConstraintMapping("/*", "role");
        demoServer.start();
    }

    public JettyDemoServer(String realm) {
        HashLoginService loginService = new HashLoginService();
        loginService.setName(realm);
        loginService.setUserStore(userStore);

        securityHandler.setAuthenticator(new DigestAuthenticator());
        securityHandler.setRealmName(realm);
        securityHandler.setLoginService(loginService);
    }

    public void addConstraintMapping(String pathSpec, String role) {
        Constraint constraint = new Constraint();
        constraint.setName(Constraint.__DIGEST_AUTH);
        constraint.setRoles(new String[]{role});
        constraint.setAuthenticate(true);
        ConstraintMapping cm = new ConstraintMapping();
        cm.setConstraint(constraint);
        cm.setPathSpec(pathSpec);
        securityHandler.addConstraintMapping(cm);
    }

    public void addUser(String user, String pass, String role) {
        userStore.addUser(user, Credential.getCredential(pass), new String[]{role});
    }

    public void start() throws Exception {
        userStore.start();

        server = new Server();
        ServletContextHandler servletHandler = new ServletContextHandler();
        servletHandler.addServlet(BlockingServlet.class, "/status");
        servletHandler.setSecurityHandler(securityHandler);
        server.setHandler(servletHandler);
        ServerConnector connector = new ServerConnector(server);
        connector.setPort(8090);
        server.setConnectors(new Connector[] {connector});
        server.start();
    }

    public void stop() throws Exception {
        server.stop();
    }

    public static class BlockingServlet extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().println("{ \"status\": \"ok\"}");
        }
    }
}
