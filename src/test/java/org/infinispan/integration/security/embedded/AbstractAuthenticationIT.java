package org.infinispan.integration.security.embedded;

import org.infinispan.Cache;
import org.infinispan.configuration.cache.AuthorizationConfigurationBuilder;
import org.infinispan.configuration.cache.ConfigurationBuilder;
import org.infinispan.configuration.global.GlobalAuthorizationConfigurationBuilder;
import org.infinispan.configuration.global.GlobalConfigurationBuilder;
import org.infinispan.configuration.global.GlobalRoleConfigurationBuilder;
import org.infinispan.integration.security.utils.AbstractServer;
import org.infinispan.manager.DefaultCacheManager;
import org.infinispan.manager.EmbeddedCacheManager;
import org.infinispan.security.AuthorizationPermission;
import org.infinispan.security.PrincipalRoleMapper;
import org.infinispan.security.impl.IdentityRoleMapper;
import org.infinispan.transaction.LockingMode;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import java.io.File;
import java.net.MalformedURLException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import static org.infinispan.integration.security.utils.Principals.*;
import static org.junit.Assert.assertEquals;

/**
 * @author vjuranek@redhat.com
 * @since 7.0
 */
public abstract class AbstractAuthenticationIT {

   public static final String CACHE_NAME = "secureCache";

   protected static AbstractServer dsServer;
   protected EmbeddedCacheManager manager;
   protected Cache<Object, Object> secureCache;
   GlobalConfigurationBuilder globalConfig;
   private ConfigurationBuilder cacheConfig;

   @Deployment
   public static WebArchive deployment() {
      WebArchive war = ShrinkWrap
            .create(WebArchive.class)
            .addAsLibraries(new File("target/test-libs/infinispan-core.jar"),
                            new File("target/test-libs/infinispan-commons.jar"),
                            new File("target/test-libs/jboss-marshalling.jar"),
                            new File("target/test-libs/jboss-marshalling-river.jar"))
            .addPackage(AbstractServer.class.getPackage())
            .addPackage(AbstractAuthenticationIT.class.getPackage())
            .addAsManifestResource("jboss-deployment-structure.xml", "jboss-deployment-structure.xml");
      return war;
   }

   @Before
   public void setupCache() throws Exception {
      //global setup
      globalConfig = new GlobalConfigurationBuilder();
      globalConfig.globalJmxStatistics().disable();
      globalConfig.globalJmxStatistics().mBeanServerLookup(null); //TODO remove once WFLY-3124 is fixed, for now fail JMX registration

      GlobalAuthorizationConfigurationBuilder globalRoles = globalConfig.security().authorization()
            .principalRoleMapper(getPrincipalRoleMapper());

      //cache setup
      cacheConfig = new ConfigurationBuilder();
      cacheConfig.transaction().lockingMode(LockingMode.PESSIMISTIC);
      cacheConfig.invocationBatching().enable();
      cacheConfig.jmxStatistics().disable();
      AuthorizationConfigurationBuilder authConfig = cacheConfig.security().enable().authorization();

      //authorization setup
      Map<String, AuthorizationPermission[]> rolePermissionMap = getRolePermissionMap();
      for (Entry<String, AuthorizationPermission[]> role : rolePermissionMap.entrySet()) {
         authConfig = authConfig.role(role.getKey());
         GlobalRoleConfigurationBuilder roleBuilder = globalRoles.role(role.getKey());
         for (AuthorizationPermission permission : role.getValue()) {
            roleBuilder = roleBuilder.permission(permission);
         }
      }

      Subject admin = getAdminSubject();
      Subject.doAs(admin, new PrivilegedExceptionAction<Void>() {
         public Void run() throws Exception {
            manager = new DefaultCacheManager(globalConfig.build());
            manager.defineConfiguration(CACHE_NAME, cacheConfig.build());
            secureCache = manager.getCache(CACHE_NAME);
            secureCache.put("predefined key", "predefined value");
            return null;
         }
      });
   }

   protected abstract PrincipalRoleMapper getPrincipalRoleMapper();

   @After
   public void tearDown() throws Exception {
      if (manager != null) {
         Subject admin = getAdminSubject();
         Subject.doAs(admin, new PrivilegedExceptionAction<Void>() {
            public Void run() throws Exception {
               manager.stop();
               return null;
            }
         });
      }
   }

   @Test
   public void testAdminCRUD() throws Exception {
      Subject admin = authenticate(ADMIN.role(), ADMIN.passwd());
      Subject.doAs(admin, new PrivilegedExceptionAction<Void>() {
         public Void run() throws Exception {
            assertEquals("predefined value", secureCache.get("predefined key"));
            secureCache.put("test", "test value");
            assertEquals("test value", secureCache.get("test"));
            Cache<Object, Object> c = manager.getCache("adminCache");
            c.start();
            c.put("test", "value");
            assertEquals("value", c.get("test"));
            c.remove("test");
            assertEquals(null, c.get("test"));
            c.stop();
            return null;
         }
      });
   }

   @Test
   public void testWriterWrite() throws Exception {
      Subject reader = authenticate(WRITER.role(), WRITER.passwd());
      Subject.doAs(reader, new PrivilegedExceptionAction<Void>() {
         public Void run() throws Exception {
            secureCache.put("test", "test value");
            return null;
         }
      });
   }

   @Test
   public void testWriterCreateWrite() throws Exception {
      Subject reader = authenticate(WRITER.role(), WRITER.passwd());
      Subject.doAs(reader, new PrivilegedExceptionAction<Void>() {
         public Void run() throws Exception {
            Cache<Object, Object> c = manager.getCache("writerCache");
            c.put("test", "value");
            return null;
         }
      });
   }

   @Test
   public void testWriterRemove() throws Exception {
      Subject reader = authenticate(WRITER.role(), WRITER.passwd());
      Subject.doAs(reader, new PrivilegedExceptionAction<Void>() {
         public Void run() throws Exception {
            secureCache.remove("predefined key");
            return null;
         }
      });
   }

   @Test(expected = SecurityException.class)
   public void testWriterRead() throws Exception {
      Subject reader = authenticate(WRITER.role(), WRITER.passwd());
      Subject.doAs(reader, new PrivilegedExceptionAction<Void>() {
         public Void run() throws Exception {
            secureCache.get("predefined key");
            return null;
         }
      });
   }

   @Test
   public void testReaderRead() throws Exception {
      Subject reader = authenticate(READER.role(), READER.passwd());
      Subject.doAs(reader, new PrivilegedExceptionAction<Void>() {
         public Void run() throws Exception {
            assertEquals("predefined value", secureCache.get("predefined key"));
            return null;
         }
      });
   }

   @Test(expected = SecurityException.class)
   public void testReaderWrite() throws Exception {
      Subject reader = authenticate(READER.role(), READER.passwd());
      Subject.doAs(reader, new PrivilegedExceptionAction<Void>() {
         public Void run() throws Exception {
            secureCache.put("test", "test value");
            return null;
         }
      });
   }

   @Test(expected = SecurityException.class)
   public void testReaderRemove() throws Exception {
      Subject reader = authenticate(READER.role(), READER.passwd());
      Subject.doAs(reader, new PrivilegedExceptionAction<Void>() {
         public Void run() throws Exception {
            secureCache.remove("predefined key");
            return null;
         }
      });
   }

   @Test(expected = SecurityException.class)
   public void testUnprivilegedRead() throws Exception {
      Subject reader = authenticate(UNPRIVILEGED.role(), UNPRIVILEGED.passwd());
      Subject.doAs(reader, new PrivilegedExceptionAction<Void>() {
         public Void run() throws Exception {
            secureCache.get("predefined key");
            return null;
         }
      });
   }

   @Test(expected = SecurityException.class)
   public void testUnprivilegedWrite() throws Exception {
      Subject reader = authenticate(UNPRIVILEGED.role(), UNPRIVILEGED.passwd());
      Subject.doAs(reader, new PrivilegedExceptionAction<Void>() {
         public Void run() throws Exception {
            secureCache.put("test", "test value");
            return null;
         }
      });
   }

   @Test(expected = SecurityException.class)
   public void testUnprivilegedRemove() throws Exception {
      Subject reader = authenticate(UNPRIVILEGED.role(), UNPRIVILEGED.passwd());
      Subject.doAs(reader, new PrivilegedExceptionAction<Void>() {
         public Void run() throws Exception {
            secureCache.remove("predefined key");
            return null;
         }
      });
   }

   @Test(expected = SecurityException.class)
   public void testUnauthenticatedRead() throws Exception {
      secureCache.get("predefined key");
   }

   @Test(expected = SecurityException.class)
   public void testUnauthenticatedWrite() throws Exception {
      secureCache.put("test", "value");
   }

   @Test(expected = SecurityException.class)
   public void testUnauthenticatedRemove() throws Exception {
      secureCache.remove("predefined key");
   }

   public Map<String, AuthorizationPermission[]> getRolePermissionMap() {
      Map<String, AuthorizationPermission[]> roles = new HashMap<String, AuthorizationPermission[]>();
      roles.put(ADMIN.role(), new AuthorizationPermission[]{AuthorizationPermission.ALL});
      roles.put(WRITER.role(), new AuthorizationPermission[]{AuthorizationPermission.WRITE});
      roles.put(READER.role(), new AuthorizationPermission[]{AuthorizationPermission.READ});
      roles.put(UNPRIVILEGED.role(), new AuthorizationPermission[]{AuthorizationPermission.NONE});

      return roles;
   }

   public Subject getAdminSubject() throws LoginException, MalformedURLException {
      return authenticate(ADMIN.role(), ADMIN.passwd());
   }

   public abstract Subject authenticate(String login, String password) throws LoginException, MalformedURLException;
}