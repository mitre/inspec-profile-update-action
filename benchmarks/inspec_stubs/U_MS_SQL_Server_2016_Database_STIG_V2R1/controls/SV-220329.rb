control 'SV-220329' do
  title 'SQL Server must use NSA-approved cryptography to protect classified information in accordance with the data owners requirements.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

It is the responsibility of the data owner to assess the cryptography requirements in light of applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

NSA-approved cryptography for classified networks is hardware based. This requirement addresses the compatibility of a DBMS with the encryption devices.'
  desc 'check', %q(Detailed information on the NIST Cryptographic Module Validation Program (CMVP) is available at the following website: http://csrc.nist.gov/groups/STM/cmvp/index.html.

Review system documentation to determine whether cryptography for classified or sensitive information is required by the information owner.

If the system documentation does not specify the type of information hosted on SQL Server: classified, sensitive, and/or unclassified, this is a finding.

If neither classified nor sensitive information exists within SQL Server databases or configuration, this is not a finding.

Verify that Windows is configured to require the use of FIPS compliant algorithms.

Click Start >> Type "Local Security Policy" >> Press Enter >> Expand "Local Policies" >> Select "Security Options" >> Locate "System Cryptography:  Use FIPS compliant algorithms for encryption, hashing, and signing".

If the Security Setting for this option is "Disabled" this is a finding.

Note: The list of acceptable algorithms: "AES 256" and "Triple DES".

If cryptography is being used by SQL Server, verify that the cryptography is NIST FIPS 140-2 certified by running the following SQL query:

SELECT DISTINCT name, algorithm_desc
FROM sys.symmetric_keys
WHERE key_algorithm NOT IN ('D3','A3')
ORDER BY name

If any items list showing an uncertified NIST FIPS 140-2 algorithm type, this is a finding.)
  desc 'fix', "Configure cryptographic functions to use NSA-approved cryptography compliant algorithms.

Use DoD code-signing certificates to create asymmetric keys stored in the database and used to encrypt sensitive data stored in the database.

Run the following SQL script to create a certificate:
USE 
CREATE CERTIFICATE 
 ENCRYPTION BY PASSWORD = <'password'>
 FROM FILE = <'path/file_name'>
 WITH SUBJECT = 'name of person creating key',
 EXPIRY_DATE = '<'expiration date: yyyymmdd'>'

Run the following SQL script to create a symmetric key and assign an existing certificate:
USE 
CREATE SYMMETRIC KEY <'key name'>
 WITH ALGORITHM = AES_256 
 ENCRYPTION BY CERTIFICATE

For Transparent Data Encryption (TDE):
USE master;
CREATE MASTER KEY ENCRYPTION BY PASSWORD = '';
CREATE CERTIFICATE  . . .;
USE ;
CREATE DATABASE ENCRYPTION KEY
WITH ALGORITHM = AES_256
ENCRYPTION BY SERVER CERTIFICATE ;
ALTER DATABASE 
SET ENCRYPTION ON;"
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Database'
  tag check_id: 'C-22044r393527_chk'
  tag severity: 'medium'
  tag gid: 'V-220329'
  tag rid: 'SV-220329r508025_rule'
  tag stig_id: 'SQL6-D0-003200'
  tag gtitle: 'SRG-APP-000416-DB-000380'
  tag fix_id: 'F-22033r393528_fix'
  tag 'documentable'
  tag legacy: ['V-79113', 'SV-93819']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
