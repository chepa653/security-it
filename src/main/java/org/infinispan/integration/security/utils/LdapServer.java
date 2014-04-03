package org.infinispan.integration.security.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author vchepeli@redhat.com
 * @since 7.0
 */
public class LdapServer extends AbstractServer {

   public static void main(String[] args) {
      runServer(args, LdapServer.class, "ispn-ldap.ldif");
   }

   @Override
//   @CreateLdapServer(transports = {@CreateTransport(protocol = "LDAP", port = LDAP_PORT)})
   public void start(String ldapInitFile) throws Exception {
      startDirectoryServer();
      startLdapServer(ldapInitFile);
   }

   @Override
   public void stop() throws Exception {
      stopLdapServer();
      stopDirectoryServer();
   }

   @Override
   public Logger getLogger() {
      return LoggerFactory.getLogger(LdapServer.class);
   }
}
