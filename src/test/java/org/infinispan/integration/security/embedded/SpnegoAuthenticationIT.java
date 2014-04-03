package org.infinispan.integration.security.embedded;

import org.infinispan.integration.security.utils.KdcServer;
import org.infinispan.integration.security.utils.Krb5LoginConfiguration;
import org.infinispan.integration.security.utils.LoginHandler;
import org.infinispan.integration.security.utils.PrincipalGroupRoleMapper;
import org.infinispan.security.PrincipalRoleMapper;
import org.jboss.arquillian.junit.Arquillian;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.net.MalformedURLException;

/**
 * @author vchepeli@redhat.com
 * @since 7.0
 */
@RunWith(Arquillian.class)
public class SpnegoAuthenticationIT extends AbstractAuthenticationIT {

   private static final String SECURITY_DOMAIN_NAME_SPNEGO = "SPNEGO";
   private static Logger LOGGER = LoggerFactory.getLogger(SpnegoAuthenticationIT.class);

   @BeforeClass
   public static void dsServerSetup() throws Exception {
      dsServer = new KdcServer();
      dsServer.start(ldapInitFile());
      System.setProperty("java.security.krb5.conf", "krb5.conf");
   }

   @AfterClass
   public static void dsServerShutdown() throws Exception {
      dsServer.stop();
   }


   protected static String ldapInitFile() {
      return System.getProperty("ldap.init.file", "ispn-krb5.ldif");
   }

   @Override
   protected PrincipalRoleMapper getPrincipalRoleMapper() {
      return new PrincipalGroupRoleMapper();
   }

   @Override
   public Subject authenticate(String login, String password) throws LoginException, MalformedURLException {
      final String securityDomain = System.getProperty("jboss.security.domain", getSecurityDomainName());
      LOGGER.debug("Starting GSS - login");
      // Use our custom configuration to avoid reliance on external config
      Configuration.setConfiguration(new Krb5LoginConfiguration(login + "@INFINISPAN.ORG", null, true));
//      Configuration.setConfiguration(new Krb5LoginConfiguration(login + "@INFINISPAN.ORG", null, true));
      // 1. Authenticate to Kerberos.
      final LoginContext lc = new LoginContext(securityDomain, new LoginHandler(login + "@INFINISPAN.ORG", password));
      lc.login();
      LOGGER.debug("Authentication succeed");

      return lc.getSubject();
   }

   private String getSecurityDomainName() {
      return SECURITY_DOMAIN_NAME_SPNEGO;
   }
}
