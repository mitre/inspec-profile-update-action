control 'SV-253739' do
  title 'MariaDB must implement cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest (to include, at a minimum, PII and classified information) on organization-defined information system components.'
  desc 'MariaDB’s handling of data requiring data at rest protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. These cryptographic mechanisms may be native to the MariaDB or implemented via additional software or operating system/file system settings, as appropriate to the situation.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields). 

The decision whether and what to encrypt rests with the data owner and is also influenced by the physical measures taken to secure the equipment and media on which the information resides.'
  desc 'check', "Review the security guide to determine whether the organization has defined the information at rest that is to be protected from modification, which must include, at a minimum, PII and classified information.

If no information is identified as requiring such protection, this is not a finding.

Review the configuration of MariaDB, operating system/file system, and additional software as relevant.
 
One possible way to encrypt data within MariaDB is to use the file key management plugin. To determine if this is installed, check the following variables as the Database administrator:

MariaDB> SHOW PLUGINS; 

Confirm the file_key_management.so is listed.

MariaDB> SHOW GLOBAL VARIABLES LIKE 'file_key%';
MariaDB> SHOW GLOBAL VARIABLES LIKE 'aria_en%';
MariaDB> SHOW GLOBAL VARIABLES LIKE 'innodb_encrypt_tables';
MariaDB> SHOW GLOBAL VARIABLES LIKE 'innodb_encrypt_log';
MariaDB> SHOW GLOBAL VARIABLES LIKE 'innodb_tablespace%';
MariaDB> SHOW GLOBAL VARIABLES LIKE 'encrypt%';

Confirm that these are ON.

If any of the information defined as requiring cryptographic protection from modification is not encrypted in a manner that provides the required level of protection, this is a finding."
  desc 'fix', 'Configure MariaDB, operating system/file system, and additional software as relevant, to provide the required level of cryptographic protection.
 
Once the File Key Management Plugin is enabled, use it by creating an encrypted table:

MariaDB> CREATE TABLE t (i int) ENGINE=InnoDB ENCRYPTED=YES;

Now, table t will be encrypted using the encryption key from the key file.'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57191r841740_chk'
  tag severity: 'medium'
  tag gid: 'V-253739'
  tag rid: 'SV-253739r841742_rule'
  tag stig_id: 'MADB-10-008600'
  tag gtitle: 'SRG-APP-000428-DB-000386'
  tag fix_id: 'F-57142r841741_fix'
  tag 'documentable'
  tag cci: ['CCI-002475']
  tag nist: ['SC-28 (1)']
end
