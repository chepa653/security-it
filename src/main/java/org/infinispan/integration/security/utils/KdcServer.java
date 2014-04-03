package org.infinispan.integration.security.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author vchepeli@redhat.com
 * @since 7.0
 */
public class KdcServer extends AbstractServer {

   public static void main(String[] args) {
      runServer(args, KdcServer.class, "ispn-krb5.ldif");
   }

   @Override
//   @CreateKdcServer(primaryRealm = "INFINISPAN.ORG",
//                    kdcPrincipal = "krbtgt/INFINISPAN.ORG@INFINISPAN.ORG",
//                    searchBaseDn = "dc=infinispan,dc=org",
//                    transports = {@CreateTransport(protocol = "UDP", port = 6088)})
//   @CreateLdapServer(transports = {@CreateTransport(protocol = "LDAP", port = AbstractServer.LDAP_PORT)}
//         , saslHost = "localhost"
//         , saslRealms = {"infinispan.org"}
//         , saslPrincipal = "ldap/localhost@INFINISPAN.ORG"
//         , saslMechanisms =
//                           {
//                                 @SaslMechanism(name = SupportedSaslMechanisms.GSSAPI, implClass = GssapiMechanismHandler.class),
//                                 @SaslMechanism(name = SupportedSaslMechanisms.NTLM, implClass = NtlmMechanismHandler.class),
//                                 @SaslMechanism(name = SupportedSaslMechanisms.GSS_SPNEGO, implClass = NtlmMechanismHandler.class)
//                           }
//   )
   public void start(String ldapInitFile) throws Exception {
      startDirectoryServer();
      startKdcServer(ldapInitFile);
   }

   @Override
   public void stop() throws Exception {
      stopKdcServer();
      stopDirectoryServer();
   }

   @Override
   public Logger getLogger() {
      return LoggerFactory.getLogger(KdcServer.class);
   }
}
