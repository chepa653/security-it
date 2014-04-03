package org.infinispan.integration.security.embedded;

import org.infinispan.integration.security.utils.LdapServer;
import org.infinispan.integration.security.utils.LoginHandler;
import org.infinispan.security.PrincipalRoleMapper;
import org.infinispan.security.impl.IdentityRoleMapper;
import org.jboss.arquillian.junit.Arquillian;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

/**
 * @author vjuranek@redhat.com
 * @author vchepeli@redhat.com
 * @since 7.0
 */
@RunWith(Arquillian.class)
public class LdapAuthenticationIT extends AbstractAuthenticationIT {

   private static final String SECURITY_DOMAIN_NAME_LDAP = "LDAP";
   private static Logger LOGGER = LoggerFactory.getLogger(LdapAuthenticationIT.class);

   @BeforeClass
   public static void dsServerSetup() throws Exception {
      dsServer = new LdapServer();
      dsServer.start(ldapInitFile());
   }

   @AfterClass
   public static void dsServerShutdown() throws Exception {
      dsServer.stop();
   }


   protected static String ldapInitFile() {
      return System.getProperty("ldap.init.file", "ispn-ldap.ldif");
   }

   @Override
   protected PrincipalRoleMapper getPrincipalRoleMapper() {
      return new IdentityRoleMapper();
   }

   @Override
   public Subject authenticate(String login, String password) throws LoginException {
      final String securityDomain = System.getProperty("jboss.security.domain", getSecurityDomainName());
      LOGGER.debug("Starting LDAP - login");
      LoginContext lc = new LoginContext(securityDomain, new LoginHandler(login, password));
      lc.login();
      LOGGER.debug("Authentication succeed");
      return lc.getSubject();
   }

   private String getSecurityDomainName() {
      return SECURITY_DOMAIN_NAME_LDAP;
   }
}
