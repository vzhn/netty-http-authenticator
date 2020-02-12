package me.vzhilin.jetty;

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

public class JettyDigestDemo {
    public static void main(String... argv) throws Exception {
        new JettyDigestDemo().start();
    }

    private void start() throws Exception {
        Server server = new Server();
        ServletContextHandler servletHandler = new ServletContextHandler();
        server.setHandler(servletHandler);
        servletHandler.addServlet(BlockingServlet.class, "/status");
        ConstraintSecurityHandler securityHandler = new ConstraintSecurityHandler();
        securityHandler.setAuthenticator(new DigestAuthenticator());
        final String realmName = "Realm";
        securityHandler.setRealmName(realmName);
        HashLoginService loginService = new HashLoginService();
        loginService.setName(realmName);
        UserStore userStore = new UserStore();
        userStore.addUser("user", Credential.getCredential("pass"), new String[]{"role"});
        userStore.start();
        loginService.setUserStore(userStore);
        securityHandler.setLoginService(loginService);
        ConstraintMapping cm = new ConstraintMapping();
        Constraint constraint = new Constraint();
        constraint.setName(Constraint.__DIGEST_AUTH);
        constraint.setRoles(new String[]{"role"});
        constraint.setAuthenticate(true);
        cm.setConstraint(constraint);
        cm.setPathSpec("/*");
        securityHandler.addConstraintMapping(cm);
        servletHandler.setSecurityHandler(securityHandler);
        ServerConnector connector = new ServerConnector(server);
        connector.setPort(8090);
        server.setConnectors(new Connector[] {connector});
        server.start();
    }

    public static class BlockingServlet extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().println("{ \"status\": \"ok\"}");
        }
    }
}
