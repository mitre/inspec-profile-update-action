control 'SV-53272' do
  title 'SQL Server must employ NSA-approved cryptography to protect classified information.'
  desc 'Cryptography is only as strong as the encryption modules/algorithms employed to encrypt the data. Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data.

NSA has developed Type 1 algorithms for protecting classified information. The Committee on National Security Systems (CNSS) National Information Assurance Glossary (CNSS Instruction No. 4009) defines Type 1 products as:
“Cryptographic equipment, assembly or component classified or certified by NSA for encrypting and decrypting classified and sensitive national security information when appropriately keyed.
Developed using established NSA business processes and containing NSA approved algorithms are used to protect systems requiring the most stringent protection mechanisms.”

NSA-approved cryptography is required to be used for classified information system processing.'
  desc 'check', %q(Review system documentation to determine whether cryptography for classified or sensitive information is required by the information owner.

If the system documentation does not specify the type of information hosted on SQL Server: classified, sensitive and/or unclassified, this is a finding.

If neither classified nor sensitive information exists within SQL Server databases or configuration, this requirement is NA.
Note:  If the SQL Server is compliant, nothing is displayed.

If cryptography is being used by SQL Server, examine evidence that an audit record is created whenever the asymmetric key is accessed by other than authorized users. In particular, view evidence that access by a SYSADMIN or other system privileged account results in the generation of an audit record. This is required because system privileges allow access to encryption keys and can be used to access sensitive data where there is not a need-to-know.

Note:  The list of acceptable algorithms: "AES 128", "AES 192", "AES 256" and "Triple DES".

If cryptography is being used by SQL Server, verify that the cryptography is NIST FIPS 140-2 certified by running the following SQL query:
EXEC sp_MSforeachdb
'
DECLARE @nCount integer;

SELECT @nCount = Count(*)
  FROM [?].sys.symmetric_keys
 WHERE key_algorithm NOT IN (''D3'',''A1'',''A2'',''A3'');

IF @nCount > 0
   SELECT ''?'' AS ''database ?''
        , name
        , algorithm_desc
     FROM [?].sys.symmetric_keys
    WHERE key_algorithm NOT IN (''D3'',''A1'',''A2'',''A3'')
    ORDER BY name, algorithm_desc;
'
;

If any items list showing an uncertified NIST FIPS 140-2 algorithm type, this is a finding.
If an audit record is not generated for unauthorized access to the asymmetric key, this is a finding.

Detailed information on the NIST Cryptographic Module Validation Program (CMVP) is available at the following website:  http://csrc.nist.gov/groups/STM/cmvp/index.html.)
  desc 'fix', "Document within the system documentation the type of information hosted on SQL Server: classified, sensitive, and/or unclassified.

Obtain and utilize native or third-party NIST-validated FIPS 140-2 compliant cryptography solution on SQL Server.

Configure cryptographic functions to use FIPS 140-2 compliant algorithms functions.

Use DoD certificates to create asymmetric keys stored in the database and used to encrypt sensitive data stored in the database.

Run the following SQL script to create a certificate:
USE <database name>
CREATE CERTIFICATE <certificate name>
   ENCRYPTION BY PASSWORD = '<password>'
   FROM FILE = '<path/file_name>'
   WITH SUBJECT = '<name of person creating key>',
   EXPIRY_DATE = '<expiration date: yyyymmdd>'

Run the following SQL script to create a symmetric key and assign an existing certificate:
USE <database name>
CREATE SYMMETRIC KEY <'key name'>
   WITH ALGORITHM = AES_256 
   ENCRYPTION BY CERTIFICATE <certificate name>

Assign the application object owner account as the owner of asymmetric and symmetric keys, and certificates.  (Ownership is assigned via the AUTHORIZATION clause of the CREATE statement, or the ALTER AUTHORIZATION statement.)

Create audit events for access to the key by other than the application owner account or approved application objects.  (If using a server-level SQL Server Audit specification, DATABASE_OBJECT_PERMISSION_CHANGE_GROUP accomplishes this.)

Revoke any privileges on encryption keys assigned to principals other than the application object owner account and authorized users.

Protect the private key by encrypting it with the database or service master key.

For whole-database encryption (Transparent Data Encryption - TDE):
USE master;
CREATE MASTER KEY ENCRYPTION BY PASSWORD = '<password>';
CREATE CERTIFICATE <certificate name> . . .;
USE <database name>;
CREATE DATABASE ENCRYPTION KEY
WITH ALGORITHM = AES_256
ENCRYPTION BY SERVER CERTIFICATE <certificate name>;
ALTER DATABASE <database name>
SET ENCRYPTION ON;"
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47573r6_chk'
  tag severity: 'medium'
  tag gid: 'V-40918'
  tag rid: 'SV-53272r6_rule'
  tag stig_id: 'SQL2-00-019800'
  tag gtitle: 'SRG-APP-000198-DB-000143'
  tag fix_id: 'F-46200r9_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
