control 'SV-250335' do
  title 'Multifactor authentication for network access to privileged accounts must be used.'
  desc 'Multifactor authentication creates a layered defense and makes it more difficult for an unauthorized person to access the application server. If one factor is compromised or broken, the attacker still has at least one more barrier to breach before successfully breaking into the target. Unlike a simple username/password scenario where the attacker could gain access by knowing both the username and password without the user knowing his account was compromised, multifactor authentication adds the requirement that the attacker must have something from the user, such as a token, or to biometrically be the user.

When accessing the application server via a network connection, administrative access to the application server must be PKI Hardware Token enabled.

The high level steps required for configuring Liberty Server to use certificate based authentication include the following:

1. Configure Web Application with client certificate authentication.
2. Configure Liberty SSL configuration with client authentication.
3. Configure Liberty LDAP Security Configuration with certificate filter.

'
  desc 'check', 'As a user with local file access to ${server.config.dir}/server.xml file, verify the TLS connection used for managing the server is configured to use clientAuthentication.

<featureManager>
<feature>appSecurity-2.0</feature>
<feature>ldapRegistry-3.0</feature>
<feature>transportSecurity-1.0</feature>
</featureManager>

Verify the TLS connection used for managing the server is configured to use clientAuthentication. The following is used as an example.

If the clientAuthentication setting for the TLS management application is not set to "true", this is a finding.

EXAMPLE:
<!-- default SSL configuration is defaultSSLSettings -->      
    <sslDefault sslRef="defaultSSLSettings" />
    <ssl id="defaultSSLSettings" keyStoreRef="defaultKeyStore" sslProtocol="SSL_TLSv2" trustStoreRef="defaultTrustStore"
clientAuthentication="true"/>

Access the web management interface via a web browser and verify TLS secured connectivity to the web based management application.'
  desc 'fix', 'Refer to IBM documentation on how to configure TLS and client based certificate authentication for additional configuration details. The following is a summary list of items needed to configure the system for certificate based authentication. Production systems and installations will vary. 

The application’s web.xml file must be configured to use client certs.

EXAMPLE:
<login-config>
    <auth-method>CLIENT-CERT</auth-method>
</login-config>

The server.xml features must be configured to use transportSecurity and an ldap configuration. 

<featureManager>
<feature>appSecurity-2.0</feature>
<feature>ldapRegistry-3.0</feature>
<feature>transportSecurity-1.0</feature>
</featureManager>

The server.xml TLS and LDAP settings must be configured. The following is an EXAMPLE only. "Default" verbiage and keystore information in the below SSL configuration will be different in production systems.

 <!-- default SSL configuration is defaultSSLSettings -->      
    <sslDefault sslRef="defaultSSLSettings" />
    <ssl id="defaultSSLSettings" keyStoreRef="defaultKeyStore" sslProtocol="SSL_TLSv2" trustStoreRef="defaultTrustStore"
clientAuthentication="true"/>

 <keyStore id="defaultKeyStore" location="key.jks" type="JKS" password="defaultPWD" />
 <keyStore id="defaultTrustStore" location="key.jks" type="JKS" password="defaultPWD" />

Configure LDAP certificate filter settings according the certificates being used.

<ldapRegistry id="ldap" realm="SampleLdapRealm" host="${ldap.server.name}" port="${ldap.server.port}" ignoreCase="true"
baseDN="${ldap.server.base.dn}"
ldapType="${ldap.vendor.type}"
certificateMapMode="Certificate_Filter" or "Exact_DN"
certificateFilter="${your certificate mapping}"
searchTimeout="8m"
sslEnabled="true">
</ldapRegistry>'
  impact 0.7
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53770r862981_chk'
  tag severity: 'high'
  tag gid: 'V-250335'
  tag rid: 'SV-250335r862983_rule'
  tag stig_id: 'IBMW-LS-000390'
  tag gtitle: 'SRG-APP-000149-AS-000102'
  tag fix_id: 'F-53724r862982_fix'
  tag satisfies: ['SRG-APP-000149-AS-000102', 'SRG-APP-000151-AS-000103', 'SRG-APP-000402-AS-000247', 'SRG-APP-000403-AS-000248', 'SRG-APP-000177-AS-000126']
  tag 'documentable'
  tag cci: ['CCI-000187', 'CCI-000765', 'CCI-000767', 'CCI-002009', 'CCI-002010']
  tag nist: ['IA-5 (2) (a) (2)', 'IA-2 (1)', 'IA-2 (3)', 'IA-8 (1)', 'IA-8 (1)']
end
