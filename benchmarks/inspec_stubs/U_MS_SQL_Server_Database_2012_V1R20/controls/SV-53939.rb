control 'SV-53939' do
  title 'SQL Server must encrypt information stored in the database.'
  desc 'When data is written to digital media, such as hard drives, mobile computers, external/removable hard drives, personal digital assistants, flash/thumb drives, etc., there is risk of data loss and/or compromise.

An organizational assessment of risk guides the selection of media and associated information contained on that media requiring restricted access. Organizations need to document, in policy and procedures, the media requiring restricted access, individuals authorized to access the media, and the specific measures taken to restrict access.

Fewer protection measures are needed for media containing information determined by the organization to be in the public domain, to be publicly releasable, or to have limited or no adverse impact if accessed by other than authorized personnel. In these situations, it is assumed the physical access controls where the media resides provide adequate protection.

As part of a defense-in-depth strategy, the organization considers routinely encrypting information at rest on selected secondary storage devices. The decision whether to employ cryptography is the responsibility of the information owner/steward, who exercises discretion within the framework of applicable rules, policies and law. The selection of the cryptographic mechanisms used is based upon maintaining the confidentiality and integrity of the information.

The strength of mechanisms is commensurate with the classification and sensitivity of the information.

Information at rest, when not encrypted, is open to compromise from attackers who have gained unauthorized access to the data files.'
  desc 'check', "Review SQL Server's cryptographic settings to determine whether data stored in databases is encrypted according to organizational requirements and the system owner.

If all of the data on SQL Server is unclassified and encryption of information is not required, this requirement is NA.

Ensure the data is encrypted by executing:
USE <databse name>;
IF NOT EXISTS
      (
      SELECT 1
      FROM sys.dm_database_encryption_keys
      WHERE DB_NAME(database_id) = DB_NAME()
      )
      SELECT
            DB_NAME() AS [Database Name],
            'No database encryption key present, no encryption' AS [Encryption State]
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
            END AS [Encryption State]
      FROM sys.dm_database_encryption_keys
      WHERE DB_NAME(database_id) = DB_NAME()
;

If any database that is supposed to have encryption enabled is not listed as such, this is a finding.

If encryption is required by the information owner and an approved, NIST-certified cryptography is not used to encrypt stored sensitive information, this is a finding.

Verify all sensitive information is encrypted: entire database, tables, columns and/or data elements, as required by the organization and the system owner."
  desc 'fix', "Use third-party tools or configure SQL Server to encrypt data stored in the database. Use only NIST-certified or NSA-approved cryptography to provide encryption.

Run the following SQL script to create a certificate:
USE <'database name'>
CREATE CERTIFICATE <'certificate name'>
   ENCRYPTION BY PASSWORD = '<'password'>'
   FROM FILE = <'path/file_name'>
   WITH SUBJECT = 'name of person creating key',
   EXPIRY_DATE = '<'expiration date: yyyymmdd'>'

Run the following SQL script to create a symmetric key and assign an existing certificate:
USE <'database name'>
CREATE SYMMETRIC KEY <'key name'>
   WITH ALGORITHM = AES_256 
   ENCRYPTION BY <'certificate name'>

Set SQL Server configuration settings to encrypt databases, tables, columns, and/or data elements as required by the organization and the system owner.

Document all instances of acceptance of risk by the information owner where sensitive or classified data is not encrypted. Have the ISSO document assurance that the unencrypted sensitive or classified information is otherwise inaccessible to those who do not have need-to-know access to the data. Developers should consider using a record-specific encryption method to protect individual records. For example, by employing the session username or other individualized element as part of the encryption key, then decryption of a data element is only possible by that user or other data accessible only by that user. Data labeling can be helpful in implementation. Consider applying additional auditing of access to any unencrypted sensitive or classified data when accessed by users (with and/or without a need to know)."
  impact 0.5
  ref 'DPMS Target SQL Server Database 2012'
  tag check_id: 'C-47947r4_chk'
  tag severity: 'medium'
  tag gid: 'V-41411'
  tag rid: 'SV-53939r5_rule'
  tag stig_id: 'SQL2-00-019300'
  tag gtitle: 'SRG-APP-000188-DB-000121'
  tag fix_id: 'F-46838r4_fix'
  tag 'documentable'
  tag cci: ['CCI-002262']
  tag nist: ['AC-16 a']
end
