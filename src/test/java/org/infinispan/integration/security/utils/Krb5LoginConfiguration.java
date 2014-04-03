package org.infinispan.integration.security.utils;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import java.io.File;
import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.Map;

/**
 * Simple Krb5LoginModule configuration.
 *
 * @author Josef Cacek
 */
public class Krb5LoginConfiguration extends Configuration {

   // get java vendor, IBM or Oracle
   private static final String JAVA_VENDOR = System.getProperty("java.vendor");
   /** The list with configuration entries. */
    private final AppConfigurationEntry[] configList = new AppConfigurationEntry[1];

    /**
     * Create a new Krb5LoginConfiguration. Neither principal nor keytab are not filled and JGSS credential type is initiator.
     *
     * @throws java.net.MalformedURLException
     */
    public Krb5LoginConfiguration() throws MalformedURLException {
        this(null, null, false);
    }

    /**
     * Create a new Krb5LoginConfiguration with given principal name, keytab and credential type.
     *
     * @param principal principal name, may be <code>null</code>
     * @param keyTab keytab file, may be <code>null</code>
     * @param acceptor flag for setting credential type. Set to true, if the authenticated subject should be acceptor (i.e.
     *        credsType=acceptor for IBM JDK, and storeKey=true for Oracle JDK)
     * @throws java.net.MalformedURLException
     */
    public Krb5LoginConfiguration(final String principal, final File keyTab, final boolean acceptor)
            throws MalformedURLException {
        final String loginModule = getLoginModule();
        Map<String, String> options = getOptions(principal, keyTab, acceptor);
        configList[0] = new AppConfigurationEntry(loginModule, AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
    }

    public static Map<String, String> getOptions() {
        return getOptions(null, null, false);
    }

    public static Map<String, String> getOptions(final String principal, final File keyTab, final boolean acceptor) {
        final Map<String, String> res = new HashMap<String, String>();

        if (JAVA_VENDOR.startsWith("IBM")) {
            if (keyTab != null) {
                res.put("useKeytab", keyTab.toURI().toString());
            }
            if (acceptor) {
                res.put("credsType", "acceptor");
            } else {
                res.put("noAddress", "true");
            }
        } else {
            if (keyTab != null) {
                res.put("keyTab", keyTab.getAbsolutePath());
                res.put("doNotPrompt", "true");
                res.put("useKeyTab", "true");
            }
            if (acceptor) {
                res.put("storeKey", "true");
            }
        }

        res.put("refreshKrb5Config", "true");
        res.put("debug", "true");

        if (principal != null) {
            res.put("principal", principal);
        }

        return res;
    }

    public static String getLoginModule() {
        if (JAVA_VENDOR.startsWith("IBM")) {
            return "com.ibm.security.auth.module.Krb5LoginModule";
        } else {
            return "com.sun.security.auth.module.Krb5LoginModule";
        }
    }

    /**
     * Interface method requiring us to return all the LoginModules we know about.
     *
     * @param applicationName the application name
     * @return the configuration entry
     */
    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry(String applicationName) {
        // We will ignore the applicationName, since we want all apps to use Kerberos V5
        return configList;
    }
}
