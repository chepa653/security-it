package org.infinispan.integration.security.utils;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import sun.misc.BASE64Encoder;

import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

public class ServiceTicketGenerator implements PrivilegedExceptionAction<byte[]> {

   private String client;
   private String service;

   public ServiceTicketGenerator(String client, String service) {
      this.client = client;
      this.service = service;
   }

   public byte[] run() throws Exception {
      try {
         return createTicket();

      } catch (Exception ex) {
         throw new PrivilegedActionException(ex);
      }
   }

   public byte[] createTicket() throws GSSException {
      // GSSAPI is generic, but if you give it the following Object ID,
      // it will create Kerberos 5 service tickets
      Oid kerberos5Oid = new Oid("1.2.840.113554.1.2.2");

      // create a GSSManager, which will do the work
      GSSManager gssManager = GSSManager.getInstance();

      // tell the GSSManager the Kerberos name of the client and service (substitute your appropriate names here)
      GSSName clientName = gssManager.createName(client + "@INFINISPAN.ORG", GSSName.NT_USER_NAME);
      GSSName serviceName = gssManager.createName(service + "/localhost@INFINISPAN.ORG", GSSName.NT_HOSTBASED_SERVICE);

      // get the client's credentials. note that this run() method was called by Subject.doAs(),
      // so the client's credentials (Kerberos TGT or Ticket-Granting Ticket) are already available in the Subject
      GSSCredential clientCredentials = gssManager.createCredential(clientName, 8 * 60 * 60, kerberos5Oid, GSSCredential.INITIATE_ONLY);

      // create a security context between the client and the service
      GSSContext gssContext = gssManager.createContext(serviceName, kerberos5Oid, clientCredentials, GSSContext.DEFAULT_LIFETIME);

      // initialize the security context
      // this operation will cause a Kerberos request of Active Directory,
      // to create a service ticket for the client to use the service
      byte[] serviceTicket = gssContext.initSecContext(new byte[0], 0, 0);
      System.out.println(new BASE64Encoder().encode(serviceTicket));
      gssContext.dispose();

      // return the Kerberos service ticket as an array of encrypted bytes
      return serviceTicket;
   }
}