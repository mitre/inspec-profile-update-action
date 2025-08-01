control 'SV-250323' do
  title 'The WebSphere Liberty Server Quality of Protection (QoP) must be set to use TLSv1.2 or higher.'
  desc 'Quality of Protection in WebSphere Liberty specifies the security level, ciphers, and mutual authentication settings for the Secure Socket Layer (SSL/TLS) configuration. For Quality of Protection settings to apply, the security feature (appSecurity-2.0) must be defined in order to configure a user registry for the servlet to authenticate against. The SSL feature (ssl-1.0) must be defined in order to configure ssl settings, and the ldap feature (ldapRegistry-3.0) must be defined in order to configure an enterprise-level user registry for authentication of users.'
  desc 'check', 'As a privileged user with local file access to ${server.config.dir}/server.xml, verify the appSecurity-x.x feature and the sslProtocol settings are configured.

grep -i appsecurity- server.xml

RESULT:
<feature>appSecurity-2.0</feature>

Verify the SSL protocol setting is configured for TLSV1.2 for every SSL configuration. There can be multiple SSL configurations and SSL ID settings.

grep -i "<ssl id=" server.xml

SAMPLE RESULT:
<ssl id="TLSSettings" keyStoreRef="TLSKeyStore" trustStoreRef="TLSTrustStore" sslProtocol="TLSv1.2"/>

If the SSL protocol setting does not specify TLS v.1.2 or higher, or if the appSecurity feature is not configured, this is a finding.'
  desc 'fix', 'To ensure the QoP is set to TLS v1.2 or higher, the ${server.config.dir}/server.xml file must be configured as follows: 

<featureManager><feature>appSecurity-2.0</feature><feature>ssl-1.0</feature></featureManager>

For every SSL configuration, the sslProtocol field must be set to TLS v1.2 or higher.

 <ssl id="TLSSettings" keyStoreRef="TLSKeyStore" trustStoreRef="TLSTrustStore"  sslProtocol="TLSv1.2" />'
  impact 0.5
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53758r862963_chk'
  tag severity: 'medium'
  tag gid: 'V-250323'
  tag rid: 'SV-250323r862965_rule'
  tag stig_id: 'IBMW-LS-000020'
  tag gtitle: 'SRG-APP-000014-AS-000009'
  tag fix_id: 'F-53712r862964_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
