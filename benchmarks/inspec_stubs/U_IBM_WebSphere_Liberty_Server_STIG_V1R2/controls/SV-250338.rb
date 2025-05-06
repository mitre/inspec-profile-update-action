control 'SV-250338' do
  title 'The WebSphere Liberty Server must use DoD-issued/signed certificates.'
  desc 'The cornerstone of PKI is the private key used to encrypt or digitally sign information. The key by itself is a cryptographic value that does not contain specific user information, but the key can be mapped to a user. Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.

'
  desc 'check', 'As a privileged user with access to the ${server.config.dir}/server.xml file; search for SSLDefault in order to identify the default SSL configuration.

grep -i ssldefault server.xml

Identify the default ssl configuration by examining the sslRef flag.

SAMPLE:
 <sslDefault sslRef="DefaultTLSSettings" /> 

Review the default ssl configuration to identify the default truststore.

SAMPLE:
 <ssl id="DefaultTLSSettings" keyStoreRef="defaultKeyStore" />
       <keyStore id="LDAPTrustStore" location="${server.config.dir}/liberty.ks" type="JKS" password="xxxxxxx" />

Use the java keytool or ikeyman utilities to open and examine the certificates stored in the truststore.

If the certificates are self signed or not signed by a DoD approved CA, this is a finding.'
  desc 'fix', 'Do not use self-signed certificates in a production environment. Only import certificates signed by an authorized DoD CA or authorized for DoD use. 

Obtain the signer certificate either as a Base 64-encoded ASCII file or as binary DER data. 

Using the JDK’s ikeyman or keytool utility, open the default trusted keystore specified in the ${server.config.dir}/server.xml. 

Click on signer certificates and import the file that contains the DoD signed certificate.'
  impact 0.5
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53773r850894_chk'
  tag severity: 'medium'
  tag gid: 'V-250338'
  tag rid: 'SV-250338r850895_rule'
  tag stig_id: 'IBMW-LS-000500'
  tag gtitle: 'SRG-APP-000177-AS-000126'
  tag fix_id: 'F-53727r795066_fix'
  tag satisfies: ['SRG-APP-000177-AS-000126', 'SRG-APP-000427-AS-000264', 'SRG-APP-000514-AS-000137']
  tag 'documentable'
  tag cci: ['CCI-000187', 'CCI-002450', 'CCI-002470']
  tag nist: ['IA-5 (2) (a) (2)', 'SC-13 b', 'SC-23 (5)']
end
