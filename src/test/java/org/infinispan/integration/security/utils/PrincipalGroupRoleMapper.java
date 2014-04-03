package org.infinispan.integration.security.utils;

import org.infinispan.security.PrincipalRoleMapper;
import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;

import java.security.Principal;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

/**
 * @author vjuranek@redhat.com
 * @since 7.0
 */
public class PrincipalGroupRoleMapper implements PrincipalRoleMapper {
   @Override
   public Set<String> principalToRoles(Principal principal) {
      if (principal instanceof SimpleGroup) {
         Enumeration<Principal> members = ((SimpleGroup) principal).members();
         if (members.hasMoreElements()) {
            Set<String> roles = new HashSet<String>();
            while (members.hasMoreElements()) {
               Principal innerPrincipal = members.nextElement();
               if (innerPrincipal instanceof SimplePrincipal) {
                  SimplePrincipal sp = (SimplePrincipal) innerPrincipal;
                  roles.add(sp.getName());
               }
            }
            return roles;
         }
      }
      return null;
   }
}
