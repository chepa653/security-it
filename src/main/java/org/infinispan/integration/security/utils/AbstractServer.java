package org.infinispan.integration.security.utils;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.directory.api.ldap.model.constants.SupportedSaslMechanisms;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.ldif.LdifReader;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.server.annotations.CreateKdcServer;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.annotations.SaslMechanism;
import org.apache.directory.server.core.annotations.AnnotationUtils;
import org.apache.directory.server.core.annotations.ContextEntry;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreateIndex;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.factory.DSAnnotationProcessor;
import org.apache.directory.server.core.kerberos.KeyDerivationInterceptor;
import org.apache.directory.server.factory.ServerAnnotationProcessor;
import org.apache.directory.server.kerberos.kdc.KdcServer;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.ldap.handlers.sasl.gssapi.GssapiMechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.ntlm.NtlmMechanismHandler;
import org.slf4j.Logger;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;

/**
 * @author vchepeli@redhat.com
 * @author jcacek@redhat.com
 * @since 7.0
 */
public abstract class AbstractServer {
   public static final int LDAP_PORT = 10389;
   protected static final String STOP_CMD = "stop";
   protected static final int SOCKET_TIMEOUT = 2000;
   protected static final int SERVER_PORT = 10959;
   private final org.slf4j.Logger LOGGER = getLogger();

   protected DirectoryService directoryService;
   protected LdapServer ldapServer;
   protected KdcServer kdcServer;

   @CreateDS(
         name = "InfinispanDS",
         partitions =
               {
                     @CreatePartition(
                           name = "infinispan",
                           suffix = "dc=infinispan,dc=org",
                           contextEntry = @ContextEntry(
                                 entryLdif =
                                       "dn: dc=infinispan,dc=org\n" +
                                             "dc: infinispan\n" +
                                             "objectClass: top\n" +
                                             "objectClass: domain\n\n"),
                           indexes =
                                 {
                                       @CreateIndex(attribute = "objectClass"),
                                       @CreateIndex(attribute = "dc"),
                                       @CreateIndex(attribute = "ou")
                                 })
               },
         additionalInterceptors = {KeyDerivationInterceptor.class})
   public void startDirectoryServer() throws Exception {
      LOGGER.info("Create Directory Service");
      directoryService = DSAnnotationProcessor.getDirectoryService();
   }

   public void stopDirectoryServer() throws Exception {
      LOGGER.info("Stoping Directory Service");
      directoryService.shutdown();
      LOGGER.info("Removing Directory Service workfiles");
      FileUtils.deleteDirectory(directoryService.getInstanceLayout().getInstanceDirectory());
   }

   @CreateKdcServer(primaryRealm = "INFINISPAN.ORG",
                    kdcPrincipal = "krbtgt/INFINISPAN.ORG@INFINISPAN.ORG",
                    searchBaseDn = "dc=infinispan,dc=org",
                    transports = {@CreateTransport(protocol = "UDP", port = 6088)})
   @CreateLdapServer(transports = {@CreateTransport(protocol = "LDAP", port = AbstractServer.LDAP_PORT)}
         , saslHost = "localhost"
         , saslRealms = {"infinispan.org"}
         , saslPrincipal = "ldap/localhost@INFINISPAN.ORG"
         , saslMechanisms =
                           {
                                 @SaslMechanism(name = SupportedSaslMechanisms.GSSAPI, implClass = GssapiMechanismHandler.class),
                                 @SaslMechanism(name = SupportedSaslMechanisms.NTLM, implClass = NtlmMechanismHandler.class),
                                 @SaslMechanism(name = SupportedSaslMechanisms.GSS_SPNEGO, implClass = NtlmMechanismHandler.class)
                           }
   )
   public void startKdcServer(String ldapInitFile) throws Exception {
      LOGGER.info("Initializing KDC server with binding to '{}'", "kdc.infinispan.org");
      kdcServer = ServerAnnotationProcessor.getKdcServer(directoryService, 1024);
      LOGGER.info(">>>KdcServer instance" + kdcServer);

      createLdapServer(ldapInitFile);
   }

   public void stopKdcServer() {
      LOGGER.info("Stoping Kerberos server");
      kdcServer.stop();

      stopLdapServer();
   }

   private void createLdapServer(String ldapInitFile) throws Exception {
      populatingPrincipals(ldapInitFile);
      LOGGER.info("Creating LDAP server");
      final CreateLdapServer createLdapServer = (CreateLdapServer) AnnotationUtils.getInstance(CreateLdapServer.class);
      ldapServer = ServerAnnotationProcessor.instantiateLdapServer(createLdapServer, directoryService);
      LOGGER.info("Starting LDAP server");
      ldapServer.start();
   }

   @CreateLdapServer(transports = {@CreateTransport(protocol = "LDAP", port = LDAP_PORT)})
   public void startLdapServer(String ldapInitFile) throws Exception {
      createLdapServer(ldapInitFile);
   }

   public void stopLdapServer() {
      LOGGER.info("Stopping LDAP server");
      ldapServer.stop();
   }

   private void populatingPrincipals(String ldapInitFile) throws IOException, LdapException {
      LOGGER.info("Populating LDAP server with users");
      final String ldifContent = IOUtils.toString(getClass().getClassLoader().getResource(ldapInitFile));
      final SchemaManager schemaManager = directoryService.getSchemaManager();
      try {
         for (LdifEntry ldifEntry : new LdifReader(IOUtils.toInputStream(ldifContent))) {
            directoryService.getAdminSession().add(new DefaultEntry(schemaManager, ldifEntry.getEntry()));
         }
      } catch (Exception e) {
         e.printStackTrace();
         throw e;
      }
   }

   protected static <T> void runServer(String[] args, Class<T> clazz, String ldifInitFile) {
      try {
         if (args.length == 1 && STOP_CMD.equals(args[0])) {
            System.out.println("Sending STOP command to Kerberos controll process.");
            SocketAddress sockaddr = new InetSocketAddress(InetAddress.getLocalHost(), SERVER_PORT);
            // Create an unbound socket
            Socket sock = new Socket();
            sock.connect(sockaddr, SOCKET_TIMEOUT);
            BufferedWriter wr = new BufferedWriter(new OutputStreamWriter(sock.getOutputStream()));
            wr.write(STOP_CMD);
            wr.close();
            sock.close();
         } else {
            System.out.println("Starting Kerberos controll process.");
            T instance = clazz.newInstance();
            if (instance instanceof AbstractServer) {
               AbstractServer ds = (AbstractServer) instance;
               ds.start(ldifInitFile);
               ds.waitForStop();
               ds.stop();
            }
         }
      } catch (Exception e) {
         e.printStackTrace();
         System.exit(1);
      }
   }

   protected void waitForStop() throws Exception {
      final ServerSocket srv = new ServerSocket(SERVER_PORT);
      boolean isStop = false;
      do {
         // Wait for connection from client.
         Socket socket = srv.accept();
         System.out.println("Incomming connection.");
         socket.setSoTimeout(SOCKET_TIMEOUT);
         BufferedReader rd = new BufferedReader(new InputStreamReader(socket.getInputStream()));
         try {
            isStop = STOP_CMD.equals(rd.readLine());
         } finally {
            rd.close();
         }
         System.out.println("Stop command: " + isStop);
         socket.close();
      } while (!isStop);
   }

   public abstract void start(String ldapInitFile) throws Exception;

   public abstract void stop() throws Exception;

   protected abstract Logger getLogger();
}