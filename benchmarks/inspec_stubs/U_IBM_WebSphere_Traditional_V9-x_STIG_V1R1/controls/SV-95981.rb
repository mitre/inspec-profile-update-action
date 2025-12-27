control 'SV-95981' do
  title 'The WebSphere Application Server must be configured to sign log information.'
  desc 'Protection of log records is of critical importance. Encrypting log records provides a level of protection that does not rely on host-based protections that can be accidentally misconfigured, such as file system permissions. Cryptographic mechanisms are the industry-established standard used to protect the integrity of log data. An example of a cryptographic mechanism is the computation and application of a cryptographic-signed hash using asymmetric cryptography.'
  desc 'check', 'From the administrative console, click Security >> Security Auditing >> Audit record signing configuration.

If the "Enable signing" checkbox is not selected, this is a finding.'
  desc 'fix', 'From the administrative console, click Security >> Security Auditing >> Audit record signing configuration.

Select the "Enable signing" checkbox.

Select the keystore that contains the encrypting certificate from the drop-down menu.

If you are using an existing certificate to sign your audit records, ensure the Certificate in keystore is selected and specify the intended certificate in the "Certificate alias" drop-down menu.

If you are generating a new certificate to sign your audit records, do NOT use the "Create a new certificate in the selected keystore" option, this will generate a SHA-1 signed certificate, which is not allowed.

Instead, select Security >> SSL Certificate and key management >> KeyStores and Certificates.

Select the keystore that is associated with the server hosting the audit logs.

Select "Personal Certificates".

Select "Create".

Select either a CA-Signed or Chained Certificate based on your requirements.

Fill in the information required to generate the certificate.

Restart the DMGR and all the JVMs.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80965r2_chk'
  tag severity: 'medium'
  tag gid: 'V-81267'
  tag rid: 'SV-95981r1_rule'
  tag stig_id: 'WBSP-AS-000820'
  tag gtitle: 'SRG-APP-000126-AS-000085'
  tag fix_id: 'F-88047r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001350']
  tag nist: ['AU-9 (3)']
end
