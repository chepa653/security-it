package org.infinispan.integration.security.utils;

/**
 * @author vchepeli@redhat.com
 * @since 7.0
 */
public enum Principals {

   ADMIN("admin", "strong_password"),
   WRITER("writer", "some_password"),
   READER("reader", "password"),
   UNPRIVILEGED("unprivileged", "weak_password"),
   // SPNEGO service principal
   SPNEGO("spnego", "hackpwd");

   private final String role;
   private final String password;
   private final String keytab;

   Principals(final String role, final String password) {
      this.role = role;
      this.password = password;
      this.keytab = role() + ".keytab";
   }

   public String role() {
      return role;
   }

   public String passwd() {
      return password;
   }

   public String keytab() {
      return keytab;
   }
}
