control 'SV-255320' do
  title 'Azure SQL Database must use NSA-approved cryptography to protect classified information in accordance with the data owners requirements.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.
It is the responsibility of the data owner to assess the cryptography requirements in light of applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

NSA-approved cryptography for classified networks is hardware based. This requirement addresses the compatibility of Azure SQL Database with the encryption devices.'
  desc 'check', 'Use the TSQL query below to determine database encryption state:

SELECT DB_NAME(database_id) AS DatabaseName, 
encryption_state_desc AS EncryptionState,
key_algorithm+CAST(key_length AS nvarchar(128)) AS EncryptionAlgorithm,
encryptor_type
FROM sys.dm_database_encryption_keys

Validate that for each database the [EncryptionState] is "ENCRYPTED" and the [EncryptionAlgorithm] returns one of the following values: [AES128], [AES192], or [AES256]. 

If any other value is returned for either the [EncryptionState] or [EncryptionAlgorithm], this is a finding.'
  desc 'fix', 'Use the ALTER DATABASE command to enable encryption on the database.

ALTER DATABASE [Database Name Between Brackets] SET ENCRYPTION ON'
  impact 0.7
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-58993r877278_chk'
  tag severity: 'high'
  tag gid: 'V-255320'
  tag rid: 'SV-255320r879944_rule'
  tag stig_id: 'ASQL-00-003200'
  tag gtitle: 'SRG-APP-000416-DB-000380'
  tag fix_id: 'F-58937r871085_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
