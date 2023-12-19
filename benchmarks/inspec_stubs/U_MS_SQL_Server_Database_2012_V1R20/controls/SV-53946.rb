control 'SV-53946' do
  title 'Symmetric keys (other than the database master key) must use a DoD certificate to encrypt the key.'
  desc 'Data within the database is protected by use of encryption. The symmetric keys are critical for this process. If the symmetric keys were to be compromised the data could be disclosed to unauthorized personnel.'
  desc 'check', "In a query tool:
USE <database name>;
GO
SELECT s.name, k.crypt_type_desc
FROM sys.symmetric_keys s, sys.key_encryptions k
WHERE s.symmetric_key_id = k.key_id
AND s.name <> '##MS_DatabaseMasterKey##'
AND k.crypt_type IN ('ESKP', 'ESKS')
ORDER BY s.name, k.crypt_type_desc;
GO

Review any symmetric keys that have been defined against the System Security Plan.

If any keys are defined that are not documented in the System Security Plan, this is a finding.

Review the System Security Plan to review the encryption mechanism specified for each symmetric key. If the method does not indicate use of certificates, this is a finding.

If the certificate specified is not a DoD PKI certificate, this is a finding."
  desc 'fix', 'Configure or alter symmetric keys to encrypt keys with certificates or authorized asymmetric keys.
From the query prompt:
ALTER SYMMETRIC KEY [key name] ADD ENCRYPTION BY CERTIFICATE [certificate name]
ALTER SYMMETRIC KEY [key name] DROP ENCRYPTION BY [password, symmetric key or asymmetric key]

The symmetric key must specify a certificate or asymmetric key for encryption.'
  impact 0.5
  ref 'DPMS Target SQL Server Database 2012'
  tag check_id: 'C-47953r6_chk'
  tag severity: 'medium'
  tag gid: 'V-41417'
  tag rid: 'SV-53946r5_rule'
  tag stig_id: 'SQL2-00-024300'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-46846r4_fix'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
