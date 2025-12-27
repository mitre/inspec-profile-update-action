control 'SV-53949' do
  title 'SQL Server must employ cryptographic mechanisms preventing the unauthorized disclosure of information at rest.'
  desc 'This control is intended to address the confidentiality and integrity of information at rest in non-mobile devices and covers user information and system information. If the data is not encrypted, it is subject to compromise and unauthorized disclosure.

Note:  the system databases (master, msdb, model, resource and tempdb) cannot be encrypted.

The decision whether to employ cryptography is the responsibility of the information owner/steward, who exercises discretion within the framework of applicable rules, policies and law.'
  desc 'check', "If this is a system database (master, msdb, resource, tempdb or model), this is not applicable (NA).

If the application owner and authorizing official have determined that the database does not require encryption, this is not a finding.

Ensure the data is encrypted by executing:
USE <database name>;
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
		DB_NAME(database_id)  AS [Database Name],
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

For each user database, ensure that encryption is in effect.  If not, this is a finding."
  desc 'fix', 'Use encryption to protect the data. To enable database encryption, create a master key, create a database encryption key, and protect it by using mechanisms tied to the master key, and then set encryption on.'
  impact 0.5
  ref 'DPMS Target SQL Server Database 2012'
  tag check_id: 'C-47955r7_chk'
  tag severity: 'medium'
  tag gid: 'V-41420'
  tag rid: 'SV-53949r6_rule'
  tag stig_id: 'SQL2-00-021400'
  tag gtitle: 'SRG-APP-000232-DB-000155'
  tag fix_id: 'F-46848r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end
