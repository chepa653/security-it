<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                version="2.0"
        >
    <xsl:output method="xml" indent="yes"/>

    <xsl:variable name="nsS" select="'urn:jboss:domain:security:'"/>
    <xsl:variable name="nsL" select="'urn:jboss:domain:logging:'"/>

    <xsl:param name="ldap.domain.name" select="'LDAP'"/>
    <xsl:param name="krb5.domain.name" select="'KRB5'"/>
    <xsl:param name="spnego.domain.name" select="'SPNEGO'"/>

    <xsl:param name="keytab.file" select="'spnego.keytab'"/>
    <!--<xsl:param name="krb5.conf.path" select="'/etc/krb5.conf'"/>-->

    <!--ldap security domain definition-->
    <xsl:variable name="newLDAPSecurityDomainDefinition">
        <security-domain name="{$ldap.domain.name}" cache-type="default">
            <authentication>
                <login-module code="org.jboss.security.auth.spi.LdapLoginModule" flag="required">
                    <module-option name="java.naming.factory.initial" value="com.sun.jndi.ldap.LdapCtxFactory"/>
                    <module-option name="java.naming.provider.url" value="ldap://localhost:10389"/>
                    <module-option name="java.naming.security.authentication" value="simple"/>
                    <module-option name="principalDNPrefix" value="uid="/>
                    <module-option name="principalDNSuffix" value=",ou=People,dc=infinispan,dc=org"/>
                    <module-option name="rolesCtxDN" value="ou=Roles,dc=infinispan,dc=org"/>
                    <module-option name="uidAttributeID" value="member"/>
                    <module-option name="matchOnUserDN" value="true"/>
                    <module-option name="roleAttributeID" value="cn"/>
                    <module-option name="roleAttributeIsDN" value="false"/>
                    <module-option name="searchScope" value="ONELEVEL_SCOPE"/>
                    <module-option name="throwValidateError" value="true"/>
                </login-module>
        </authentication>
        </security-domain>
    </xsl:variable>

    <!--kerberos security domain definition-->
    <xsl:variable name="newKrb5SecurityDomainDefinition">
        <security-domain name="{$krb5.domain.name}" cache-type="default">
            <authentication>
                <login-module code="Kerberos" flag="required">
                    <module-option name="storeKey" value="true"/>
                    <module-option name="useKeyTab" value="true"/>
                    <module-option name="refreshKrb5Config" value="true"/>
                    <module-option name="principal" value="spnego/localhost@INFINISPAN.ORG"/>
                    <module-option name="keyTab" value="${{jboss.server.config.dir}}/keytabs/{$keytab.file}"/>
                    <module-option name="doNotPrompt" value="true"/>
                    <module-option name="debug" value="true"/>
                    <module-option name="throwValidateError" value="true"/>
                </login-module>
            </authentication>
        </security-domain>
    </xsl:variable>

    <!--spnego security domain definition-->
    <xsl:variable name="newSPNEGOSecurityDomainDefinition">
        <security-domain name="{$spnego.domain.name}" cache-type="default">
            <authentication>
                <login-module code="SPNEGO" flag="requisite">
                    <module-option name="password-stacking" value="useFirstPass"/>
                    <module-option name="serverSecurityDomain" value="{$krb5.domain.name}"/>
                    <module-option name="removeRealmFromPrincipal" value="true"/>
                </login-module>
                <login-module code="AdvancedLdap" flag="required">
                    <module-option name="password-stacking" value="useFirstPass"/>
                    <module-option name="bindAuthentication" value="GSSAPI"/>
                    <module-option name="jaasSecurityDomain" value="{$krb5.domain.name}"/>
                    <module-option name="java.naming.factory.initial" value="com.sun.jndi.ldap.LdapCtxFactory"/>
                    <module-option name="allowEmptyPassword" value="false"/>
                    <module-option name="java.naming.provider.url" value="ldap://localhost:10389"/>
                    <module-option name="baseCtxDN" value="ou=People,dc=infinispan,dc=org"/>
                    <module-option name="baseFilter" value="(krbPrincipalName={{0}})"/>
                    <module-option name="rolesCtxDN" value="ou=Roles,dc=infinispan,dc=org"/>
                    <module-option name="roleFilter" value="(member={{1}})"/>
                    <module-option name="roleAttributeID" value="cn"/>
                    <module-option name="throwValidateError" value="true"/>
                </login-module>
            </authentication>
            <!--<mapping>-->
                <!--<mapping-module code="SimpleRoles" type="role">-->
                    <!--<module-option name="admin@INFINISPAN.ORG" value="admin"/>-->
                    <!--<module-option name="writer@INFINISPAN.ORG" value="writer"/>-->
                    <!--<module-option name="reader@INFINISPAN.ORG" value="reader"/>-->
                    <!--<module-option name="unprivileged@INFINISPAN.ORG" value="unprivileged"/>-->
                <!--</mapping-module>-->
            <!--</mapping>-->
        </security-domain>
    </xsl:variable>

    <!-- add new security domain definitions -->
    <xsl:template match="//*[local-name()='subsystem' and starts-with(namespace-uri(), $nsS)]
		         /*[local-name()='security-domains' and starts-with(namespace-uri(), $nsS)]">
        <xsl:copy>
            <xsl:copy-of select="$newLDAPSecurityDomainDefinition"/>
            <xsl:copy-of select="$newKrb5SecurityDomainDefinition"/>
            <xsl:copy-of select="$newSPNEGOSecurityDomainDefinition"/>
            <xsl:apply-templates select="@* | node()"/>
        </xsl:copy>
    </xsl:template>

    <!--setup system properties for EAP server-->
    <xsl:template match="//*[local-name()='extensions']">
        <xsl:variable name="elements-after" select="node()"/>
        <xsl:copy>
            <xsl:copy-of select="$elements-after"/>
        </xsl:copy>
        <system-properties>
            <property name="java.security.krb5.conf" value="${{jboss.server.config.dir}}/krb5.conf"/>
            <property name="java.security.krb5.debug" value="true"/>
            <property name="jboss.security.disable.secdomain.option" value="true"/>
        </system-properties>
    </xsl:template>

    <xsl:variable name="newSecurityLoggerDefinition">
        <logger category="org.jboss.security">
            <level name="TRACE"/>
        </logger>
    </xsl:variable>

    <!-- Add new security domain definition -->
    <xsl:template match="//*[local-name()='subsystem' and starts-with(namespace-uri(), $nsL)]">
        <xsl:copy>
            <xsl:copy-of select="$newSecurityLoggerDefinition"/>
            <xsl:apply-templates select="@* | node()"/>
        </xsl:copy>
    </xsl:template>

    <!-- Copy everything else. -->
    <xsl:template match="@* | node()">
        <xsl:copy>
            <xsl:apply-templates select="@* | node()"/>
        </xsl:copy>
    </xsl:template>

</xsl:stylesheet>