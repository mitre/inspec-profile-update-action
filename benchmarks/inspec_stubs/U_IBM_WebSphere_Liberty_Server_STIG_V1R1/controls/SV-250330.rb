control 'SV-250330' do
  title 'The WebSphere Liberty Server must be configured to encrypt log information.'
  desc '<0> [object Object]'
  desc 'check', 'If the system is configured to send logs to a remote ELK stack log server, as per requirement IBMW-LS-000230, (or other remote logging solution) this requirement is Not Applicable.

As a user with local file access to ${server.config.dir}/server.xml: 

1. Verify the following features are configured.

 <featureManager>
<feature>appSecurity-3.0</feature>
<feature>audit-1.0</feature>
<feature>ssl-1.0</feature>
</featureManager> 

2. Verify a keystore is configured. The following is an example:

 <keyStore
         id="auditEncKeyStore"
         password="ENTER THE ENCRYPTION KEYSTORE PASSWORD"
         location="${server.config.dir}/resources/security/AuditEncryptionKeyStore.jks"
         type="JKS" />

      <keyStore
         id="auditSignKeyStore"
         password="ENTER THE SIGNING KEYSTORE PASSWORD"
         location="${server.config.dir}/resources/security/AuditSigningKeyStore2.jks"
         type="JKS" />

3. Verify auditFileHandler encryption is enabled. Signing is optional.

<auditFileHandler 
encrypt="true"
        encryptAlias="auditencryption"
        encryptKeyStoreRef="auditEncKeyStore"
    sign="true"
        signingAlias="auditsigning2"
        signingKeyStoreRef="auditSignKeyStore">
</auditFileHandler>

If the features and keystore are not configured, and encryption is not enabled, this is a finding.'
  desc 'fix', 'If the system is configured to send logs to a remote ELK stack log server, (or other remote logging solution) as per requirement IBMW-LS-000230, this requirement is Not Applicable. 

Signing is optional. The encrypted and/or signed audit logs are found under the ${server.config.dir}/logs directory and are named audit.log for the most recent, and audit_<timestamp>.log for any archived logs. Two keystores are recommended but not required when doing both encryption and signing  (ikeyman as part of the JDK may be used) and a certificate imported into each. One keystore will contain the certificate used to encrypt the logs; the other keystore will contain the certificate used to sign the logs. The audit configuration must define the location of every keystore, their passwords, and the alias of each certificate used to encrypt and sign the logs.

1. Enable the following features:

<featureManager>
<feature>appSecurity-3.0</feature>
<feature>audit-1.0</feature>
<feature>ssl-1.0</feature>
<feature>
</featureManager> 

2. Verify a keystore is configured. The following is a JKS keystore example. PKCS12 is also a viable keystore:

 <keyStore
         id="auditEncKeyStore"
         password="ENTER THE ENCRYPTION KEYSTORE PASSWORD"
         location="${server.config.dir}/resources/security/AuditEncryptionKeyStore.jks"
         type="JKS" />

      <keyStore
         id="auditSignKeyStore"
         password="ENTER THE SIGNING KEYSTORE PASSWORD"
         location="${server.config.dir}/resources/security/AuditSigningKeyStore2.jks"
         type="JKS" />

3. Enable auditFileHandler encryption. Signing the logs is optional.

<auditFileHandler 
encrypt="true"
        encryptAlias="auditencryption"
        encryptKeyStoreRef="auditEncKeyStore"
    sign="true"
        signingAlias="auditsigning2"
        signingKeyStoreRef="auditSignKeyStore">
</auditFileHandler>'
  impact 0.5
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53765r795107_chk'
  tag severity: 'medium'
  tag gid: 'V-250330'
  tag rid: 'SV-250330r795108_rule'
  tag stig_id: 'IBMW-LS-000320'
  tag gtitle: 'SRG-APP-000126-AS-000085'
  tag fix_id: 'F-53719r795042_fix'
  tag cci: ['CCI-000162', 'CCI-001314', 'CCI-001350']
  tag nist: ['AU-9 a', 'SI-11 b', 'AU-9 (3)']
end
