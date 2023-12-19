control 'SV-253740' do
  title 'MariaDB must implement cryptographic mechanisms preventing the unauthorized disclosure of organization-defined information at rest on organization-defined information system components.'
  desc 'MariaDB’s handling of data requiring data at rest protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. These cryptographic mechanisms may be native to the MariaDB or implemented via additional software or operating system/file system settings, as appropriate to the situation.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).

The decision whether and what to encrypt rests with the data owner and is also influenced by the physical measures taken to secure the equipment and media on which the information resides.'
  desc 'check', "Review the security guide to determine whether the organization has defined the information at rest that is to be protected from modification, which must include, at a minimum, PII and classified information.

If no information is identified as requiring such protection, this is not a finding.

Review the configuration of MariaDB, operating system/file system, and additional software as relevant.
 
One possible way to encrypt data within MariaDB is to use the file key management plugin. To determine if this is installed check the following variables as the Database administrator:

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
  desc 'fix', 'Configure MariaDB, operating system/file system, and additional software as relevant, to provide the required level of cryptographic protection for information requiring cryptographic protection against disclosure.

Secure the premises, equipment, and media to provide the required level of physical protection.
 
One possible way to encrypt data within MariaDB is:
 How to Set Up and Configure MariaDB for Data-at-Rest Encryption
    Generate random encryption keys using openssl rand command.    
    $ mkdir -p /etc/mysql/encryption
    $ for i in {1..5}; do openssl rand -hex 32 >> /etc/mysql/encryption/keyfile;  done;
    Open and edit the file /etc/mysql/encryption/keyfile and add the key IDs that will be referenced when creating encrypted tables as the encryption key id. See ENCRYPTION_KEY_ID for more details. The format will be as follows: 

     <encryption_key_id1>;<hex-encoded_encryption_key1>
     <encryption_key_id2>;<hex-encoded_encryption_key2>

In the example keyfile, this looks similar to the following: 
$ cat keyfile
1;687a90b4423c10417f2483726a5901007571c16331d2ee9534333fef4e323075
2;e7bf20f1cbde9632587c2996871cff74871890d19b49e273d13def123d781e17
3;9284c9c80da9a323b3ac2c82427942dfbf1718b57255cc0bc0e2c3d6f15ac3ac
4;abf80c3a8b10643ef53a43c759227304bcffa263700a94a996810b0f0459a580
5;bdbc5f67d34a4904c4adc9771420ac2ab2bd9c6af1ec532e960335e831f02933

Create or generate a random password using the similar command from step 1:
$ openssl rand -hex 128 > /etc/mysql/encryption/keyfile.key

Before proceeding to the next step, it is important to take note of the following details about encrypting the key file: 
    The only algorithm that MariaDB currently supports to encrypt the key file is Cipher Block Chaining (CBC) mode of Advanced Encryption Standard (AES).
    The encryption key size can be 128-bits, 192-bits, or 256-bits.
    The encryption key is created from the SHA-1 hash of the encryption password.
    The encryption password has a max length of 256 characters.

To encrypt the key file using openssl enc command, run the following command: 
$ openssl enc -aes-256-cbc -md sha1 -pass file:/etc/mysql/encryption/keyfile.key -in /etc/mysql/encryption/keyfile    -out /etc/mysql/encryption/keyfile.enc

Add the following variables in the MySQL configuration file (i.e., /etc/my.cnf on RHEL-based Linux OS or /etc/mysql/my.cnf in Debian/Ubuntu Linux based OS)

[mysqld]
…
#################### DATABASE ENCRYPTION ##############################
plugin_load_add = file_key_management
file_key_management_filename = /etc/mysql/encryption/keyfile.enc
file_key_management_filekey = FILE:/etc/mysql/encryption/keyfile.key
file_key_management_encryption_algorithm = aes_cbc 
encrypt_binlog = 1 
innodb_encrypt_tables = ON
innodb_encrypt_log = ON
innodb_encryption_threads = 4
innodb_encryption_rotate_key_age = 0 # Do not rotate key
Restart MariaDB Server now
$ systemctl start mariadb 

Once the File Key Management Plugin is enabled, use it by creating an encrypted table:
CREATE TABLE t (i int) ENGINE=InnoDB ENCRYPTED=YES

Table t will be encrypted using the encryption key from the key file.'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57192r841743_chk'
  tag severity: 'medium'
  tag gid: 'V-253740'
  tag rid: 'SV-253740r841745_rule'
  tag stig_id: 'MADB-10-008700'
  tag gtitle: 'SRG-APP-000429-DB-000387'
  tag fix_id: 'F-57143r841744_fix'
  tag 'documentable'
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end
