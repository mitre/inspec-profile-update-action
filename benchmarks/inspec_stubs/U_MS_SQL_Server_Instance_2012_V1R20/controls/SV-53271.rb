control 'SV-53271' do
  title 'SQL Server databases in the classified environment, containing classified or sensitive information, must be encrypted using approved cryptography.'
  desc "Cryptography is only as strong as the encryption modules/algorithms employed to encrypt the data.

Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data.

Data files that are not encrypted are vulnerable to theft. When data files are not encrypted, they can be copied and opened on a separate system. The data can be compromised without the information owner's knowledge that the theft has even taken place.

NSA has developed Type 1 algorithms for protecting classified information. The Committee on National Security Systems (CNSS) National Information Assurance Glossary (CNSS Instruction No. 4009) defines Type 1 products as:
“Cryptographic equipment, assembly or component classified or certified by NSA for encrypting and decrypting classified and sensitive national security information when appropriately keyed.
Developed using established NSA business processes and containing NSA approved algorithms are used to protect systems requiring the most stringent protection mechanisms.”

NSA-approved cryptography is required to be used for classified information system processing.

See FIPS Publication 140-2 and related documents for guidance on approved encryption techniques and certified encryption modules."
  desc 'check', "If the system exists in the non-classified environment, this is NA.

For each database under the SQL Server instance, review the system documentation to determine whether the database holds classified or sensitive information. If it does not, this is not a finding.

If it does handle classified or sensitive information, review the system documentation and configuration to determine whether the classified information is protected by NSA- and NIST-approved cryptography.  If not, this is a finding.

If DBMS data encryption is required, ensure the status of encryption by executing:

SELECT
      d.name AS [Database Name],
      CASE e.encryption_state
            WHEN 0 THEN 'No database encryption key present, no encryption'
            WHEN 1 THEN 'Unencrypted'
            WHEN 2 THEN 'Encryption in progress'
            WHEN 3 THEN 'Encrypted'
            WHEN 4 THEN 'Key change in progress'
            WHEN 5 THEN 'Decryption in progress'
            WHEN 6 THEN 'Protection change in progress'
      END AS [Encryption State]
FROM sys.dm_database_encryption_keys e
RIGHT JOIN sys.databases d ON DB_NAME(e.database_id) = d.name
WHERE d.name NOT IN ('master','model','msdb')
ORDER BY 1
;
For each user database where encryption is required, verify that encryption is in effect. If not, this is a finding."
  desc 'fix', 'Configure SQL Server to encrypt sensitive or classified data stored in each database. Use only NIST-certified or NSA-approved cryptography to provide encryption.'
  impact 0.7
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47572r7_chk'
  tag severity: 'high'
  tag gid: 'V-40917'
  tag rid: 'SV-53271r4_rule'
  tag stig_id: 'SQL2-00-019600'
  tag gtitle: 'SRG-APP-000196-DB-000141'
  tag fix_id: 'F-46199r1_fix'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
