control 'SV-95979' do
  title 'The WebSphere Application Server must be configured to encrypt log information.'
  desc 'Protection of log records is of critical importance. Encrypting log records provides a level of protection that does not rely on host-based protections that can be accidentally misconfigured, such as file system permissions. Cryptographic mechanisms are the industry-established standard used to protect the integrity of log data. An example of a cryptographic mechanism is the computation and application of a cryptographic-signed hash using asymmetric cryptography. Encryption of log records must be tempered with architecture designs that incorporate log data into SIEM systems that read and act upon log data. Some SIEM systems may not be able to decrypt encrypted log data so encrypting the logs could be detrimental to the incident response process. This must be taken into account and addressed in the security plan.'
  desc 'check', 'Review System Security Plan documentation.

If the System Security Plan does not specify the encryption of audit records, this requirement is NA.

From the administrative console, click Security >> Security Auditing >> Audit record encryption configuration.

If the "Enable encryption" check box is not selected, this is a finding.'
  desc 'fix', 'From the administrative console, click Security >> Security Auditing >> Audit record encryption configuration.

Select the "Enable encryption" checkbox.

Select the keystore that contains the encrypting certificate from the drop-down menu or click "New" to create a new keystore.

If you are using an existing certificate to encrypt your audit records, ensure the Certificate in the keystore is selected and specify the intended certificate in the "Certificate alias" drop-down menu.

If you are generating a new certificate to encrypt your audit records, do NOT use the "Create a new certificate in the selected keystore" option, this will generate a SHA-1 signed certificate, which is not allowed.

Instead, select Security >> SSL Certificate and key management >> KeyStores and Certificates.

Select the keystore that is associated with the server hosting the audit logs.

Select "Personal Certificates".

Select "Create".

Select either a CA-Signed or Chained Certificate based on your requirements.

Fill in the information required to generate the certificate.

Restart the DMGR and all the JVMs.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80963r2_chk'
  tag severity: 'medium'
  tag gid: 'V-81265'
  tag rid: 'SV-95979r1_rule'
  tag stig_id: 'WBSP-AS-000810'
  tag gtitle: 'SRG-APP-000126-AS-000085'
  tag fix_id: 'F-88045r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001350']
  tag nist: ['AU-9 (3)']
end
