package org.infinispan.integration.security.utils;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.directory.server.kerberos.shared.crypto.encryption.KerberosKeyFactory;
import org.apache.directory.server.kerberos.shared.keytab.Keytab;
import org.apache.directory.shared.kerberos.KerberosTime;
import org.apache.directory.shared.kerberos.codec.types.EncryptionType;
import org.apache.directory.shared.kerberos.components.EncryptionKey;
import org.apache.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Map;

import static org.infinispan.integration.security.utils.Principals.*;

/**
 * @author jcacek@redhat.com
 * @author vchepeli@redhat.com
 * @since 7.0
 */
public class CreateKeytab {
   private static Logger LOGGER = Logger.getLogger(CreateKeytab.class);
   private static final String INFINISPAN_REALM = "@INFINISPAN.ORG";
   private static final File KEYTABS_DIR = new File("src/test/resources/keytabs");
   private static final String KRB5_CONF = "krb5.conf";
   private static final File KRB5_CONF_FILE = new File(KEYTABS_DIR, KRB5_CONF);

   private static void createKeyTabs(String canonicalHost) throws IOException {
      LOGGER.info("(Re)Creating workdir: " + KEYTABS_DIR.getAbsolutePath());
      FileUtils.deleteDirectory(KEYTABS_DIR);
      KEYTABS_DIR.mkdirs();

      createKeytab(SPNEGO.role() + "/" + canonicalHost + INFINISPAN_REALM, SPNEGO.passwd(), new File(KEYTABS_DIR, SPNEGO.keytab()));
      createKeytab(ADMIN.role() + INFINISPAN_REALM, ADMIN.passwd(), new File(KEYTABS_DIR, ADMIN.keytab()));
      createKeytab(WRITER.role() + INFINISPAN_REALM, WRITER.passwd(), new File(KEYTABS_DIR, WRITER.keytab()));
      createKeytab(READER.role() + INFINISPAN_REALM, READER.passwd(), new File(KEYTABS_DIR, READER.keytab()));
      createKeytab(UNPRIVILEGED.role() + INFINISPAN_REALM, UNPRIVILEGED.passwd(), new File(KEYTABS_DIR, UNPRIVILEGED.keytab()));
   }

   /**
    * Creates a keytab file for given principal.
    *
    * @param principalName
    * @param passPhrase
    * @param keytabFile
    * @throws java.io.IOException
    */
   public static void createKeytab(final String principalName, final String passPhrase, final File keytabFile) throws IOException {
      LOGGER.info("Principal name: " + principalName);
      final KerberosTime timeStamp = new KerberosTime();

      DataOutputStream dos = null;
      try {
         dos = new DataOutputStream(new FileOutputStream(keytabFile));
         dos.write(Keytab.VERSION_0X502_BYTES);

         for (Map.Entry<EncryptionType, EncryptionKey> keyEntry : KerberosKeyFactory.getKerberosKeys(principalName,
                                                                                                     passPhrase).entrySet()) {
            final EncryptionKey key = keyEntry.getValue();
            final byte keyVersion = (byte) key.getKeyVersion();
            // entries.add(new KeytabEntry(principalName, principalType, timeStamp, keyVersion, key));

            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream entryDos = new DataOutputStream(baos);
            // handle principal name
            String[] spnSplit = principalName.split("@");
            String nameComponent = spnSplit[0];
            String realm = spnSplit[1];

            String[] nameComponents = nameComponent.split("/");
            try {
               // increment for v1
               entryDos.writeShort((short) nameComponents.length);
               entryDos.writeUTF(realm);
               // write components
               for (String component : nameComponents) {
                  entryDos.writeUTF(component);
               }

               entryDos.writeInt(1); // principal type: KRB5_NT_PRINCIPAL
               entryDos.writeInt((int) (timeStamp.getTime() / 1000));
               entryDos.write(keyVersion);

               entryDos.writeShort((short) key.getKeyType().getValue());

               byte[] data = key.getKeyValue();
               entryDos.writeShort((short) data.length);
               entryDos.write(data);
            } finally {
               IOUtils.closeQuietly(entryDos);
            }
            final byte[] entryBytes = baos.toByteArray();
            dos.writeInt(entryBytes.length);
            dos.write(entryBytes);
         }
         // } catch (IOException ioe) {
      } finally {
         IOUtils.closeQuietly(dos);
      }
   }

   /**
    * The main.
    *
    * @param args
    * @throws IOException
    */
   public static void main(String[] args) throws IOException {
      createKeyTabs("localhost");
   }
}
