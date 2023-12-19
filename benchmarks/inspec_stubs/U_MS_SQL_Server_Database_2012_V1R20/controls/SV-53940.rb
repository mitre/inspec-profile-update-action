control 'SV-53940' do
  title 'SQL Server must implement required cryptographic protections using cryptographic modules complying with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.'
  desc 'Cryptography is only as strong as the encryption modules/algorithms employed to encrypt the data.

Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data.

Use of cryptography to provide confidentiality and non-repudiation is not effective unless strong methods are employed with its use. Many earlier encryption methods and modules have been broken and/or overtaken by increasing computing power. The NIST FIPS 140-2 cryptographic standards provide proven methods and strengths to employ cryptography effectively.

Detailed information on the NIST Cryptographic Module Validation Program (CMVP) is available at the following website:  http://csrc.nist.gov/groups/STM/cmvp/index.html.'
  desc 'check', %q(If encryption is not required for this database, this is not a finding.

Run the following SQL queries to review SQL Server's cryptographic settings for the database:

USE <database name> ;
IF NOT EXISTS
       (
       SELECT 1 
       FROM sys.dm_database_encryption_keys
       WHERE DB_NAME(database_id) = DB_NAME()
       )
       SELECT 
             DB_NAME() AS [Database Name],
             'No database encryption key present, no encryption' AS [Encryption State],
                     NULL AS [Algorithm],
                     NULL AS [Key Length]
ELSE
       SELECT
             DB_NAME(database_id) AS [Database Name],
             CASE encryption_state 
                   WHEN 0 THEN 'No database encryption key present, no encryption' 
                   WHEN 1 THEN 'Unencrypted' 
                   WHEN 2 THEN 'Encryption in progress' 
                   WHEN 3 THEN 'Encrypted' 
                   WHEN 4 THEN 'Key change in progress' 
                   WHEN 5 THEN 'Decryption in progress' 
                   WHEN 6 THEN 'Protection change in progress' 
             END AS [Encryption State],
                     key_algorithm AS [Algorithm],
                     key_length AS [Key Length]
       FROM sys.dm_database_encryption_keys
       WHERE DB_NAME(database_id) = DB_NAME()

SELECT DB_NAME() AS [Database], name, algorithm_desc 
FROM sys.symmetric_keys 
ORDER BY name, algorithm_desc;

Note:  The acceptable algorithms are:  "AES 128", "AES 192", "AES 256" and "Triple DES".

If SQL Server cryptographic algorithms are not listed or are found not to be compliant with applicable federal laws, Executive Orders, directives, policies, regulations, standards and guidance, this is a finding.

If the encryption state indicates that the database is unencrypted, this is a finding.)
  desc 'fix', %q(Implement required cryptographic protections using cryptographic modules complying with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

Ensure the database is backed up.

Run the following SQL to undo encryption and drop the existing database encryption key:
USE master;
GO
ALTER DATABASE <database name> SET ENCRYPTION OFF;
GO
USE <database name> ;
GO
DROP DATABASE ENCRYPTION KEY;
GO

Run the following SQL to drop a server certificate from the SQL Server instance:
USE master;
GO
DROP CERTIFICATE <certificate name>;
GO

If applicable, run the following SQL to drop a symmetric key:
USE <database name>;
GO
DROP SYMMETRIC KEY <key name>;
GO

Configure encryption to use approved encryption algorithms. Existing keys are not reconfigurable to use different algorithms.

Run SQL along the lines of the following to import an externally-created server certificate (see Microsoft documentation for options and syntax details):
USE master;
GO
CREATE CERTIFICATE <certificate name>
   FROM FILE = '<path\file_name>'
...
;
GO

Run the following SQL to create a database encryption key and encrypt the database:
USE <database name>;
GO
CREATE DATABASE ENCRYPTION KEY 
   WITH ALGORITHM = AES_256 
   ENCRYPTION BY SERVER CERTIFICATE <certificate name>;
GO
USE master;
GO
ALTER DATABASE <database name> SET ENCRYPTION ON;
GO

Note: The acceptable algorithms are: "AES 128", "AES 192", "AES 256" and "Triple DES".

If required, run the following SQL to create a symmetric key and assign an existing certificate:
USE <database name>;
GO
CREATE SYMMETRIC KEY <key name>
   WITH ALGORITHM = AES_256 
   ENCRYPTION BY CERTIFICATE <certificate name>;)
  impact 0.5
  ref 'DPMS Target SQL Server Database 2012'
  tag check_id: 'C-47949r6_chk'
  tag severity: 'medium'
  tag gid: 'V-41412'
  tag rid: 'SV-53940r5_rule'
  tag stig_id: 'SQL2-00-019500'
  tag gtitle: 'SRG-APP-000196-DB-000140'
  tag fix_id: 'F-46839r9_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
