control 'SV-250337' do
  title 'The WebSphere Liberty Server must use TLS-enabled LDAP.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

Application servers have the capability to use either certificates (tokens) or user IDs and passwords in order to authenticate. When the application server transmits or receives passwords, the passwords must be encrypted. The certificate used by LDAP to establish trust with incoming client requests must be imported into a trust keystore created on the Liberty Server (JDK ikeyman may be used to do this). The LDAP configuration must indicate it is using SSL, provide the BindDN and BindPassword and point to the trust keystore containing the LDAP certificate.'
  desc 'check', 'As a user with local file access to ${server.config.dir}/server.xml, verify TLS-enabled LDAP is in use. If TLS-Enabled LDAP is not defined within server.xml, this is a finding. 

<featureManager>
<feature>appSecurity-3.0</feature>
<feature>ssl-1.0</feature>
<feature>ldapRegistry-3.0</feature>
</featureManager> 

<ldapRegistry id="ldap" realm="SampleLdapRealm" host="${ldap.server.name}" port="${ldap.server.port}" ignoreCase="true"
baseDN="${ldap.server.base.dn}"
bindDN="${ldap.server.bind.dn}’
bindPassword="${ldap.server.bind.password}"
sslEnabled="true"
sslRef="LDAPTLSSettings"
ldapType="${ldap.vendor.type}"
searchTimeout="8m">
</ldapRegistry> 

<sslDefault sslRef="LDAPTLSSettings" />
<ssl id="LDAPTLSSettings" keyStoreRef="LDAPKeyStore" trustStoreRef="LDAPTrustStore" 
sslProtocol="TLSv1.2"/>
<keyStore id="LDAPKeyStore" location="${server.config.dir}/LdapSSLKeyStore.jks" type="JKS" password="{xor}CDo9Hgw=" />
<keyStore id="LDAPTrustStore" location="${server.config.dir}/LdapTLSTrustStore.jks" type="JKS" password="{xor}CDo9Hgw=" />'
  desc 'fix', 'To ensure the Liberty Server transmits only encrypted passwords, the ${server.config.dir}/server.xml must be configured as follows:

<featureManager>
<feature>appSecurity-3.0</feature>
<feature>ssl-1.0</feature>
<feature>ldapRegistry-3.0</feature>
<feature>servlet-3.1</feature>
<feature>ejbLite-3.1</feature>
</featureManager> 

<ldapRegistry id="ldap" realm="SampleLdapRealm" host="${ldap.server.name}" port="${ldap.server.port}" ignoreCase="true"
baseDN="${ldap.server.base.dn}"
bindDN="${ldap.server.bind.dn}’
bindPassword="${ldap.server.bind.password}"
sslEnabled="true"
sslRef="LDAPTLSSettings"
ldapType="${ldap.vendor.type}"
searchTimeout="8m">
</ldapRegistry> 

<sslDefault sslRef="LDAPTLSSettings" />
<ssl id="LDAPTLSSettings" keyStoreRef="LDAPKeyStore" trustStoreRef="LDAPTrustStore"
sslProtocol="TLSv1.2"
 />
<keyStore id="LDAPKeyStore" location="${server.config.dir}/LdapSSLKeyStore.jks" type="JKS" password="{xor}CDo9Hgw=" />
<keyStore id="LDAPTrustStore" location="${server.config.dir}/LdapTLSTrustStore.jks" type="JKS" password="{xor}CDo9Hgw=" />'
  impact 0.7
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53772r795062_chk'
  tag severity: 'high'
  tag gid: 'V-250337'
  tag rid: 'SV-250337r795064_rule'
  tag stig_id: 'IBMW-LS-000450'
  tag gtitle: 'SRG-APP-000172-AS-000120'
  tag fix_id: 'F-53726r795063_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
