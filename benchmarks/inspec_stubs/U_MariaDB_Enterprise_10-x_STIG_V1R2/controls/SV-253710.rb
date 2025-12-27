control 'SV-253710' do
  title 'MariaDB must protect the confidentiality and integrity of all information at rest.'
  desc 'This control is intended to address the confidentiality and integrity of information at rest in nonmobile devices and covers user information and system information. Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive, tape drive) within an organizational information system. Applications and application users generate information throughout the course of their application use. 

User data generated, as well as application-specific configuration data, must be protected. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate. 

If the confidentiality and integrity of application data is not protected, the data will be open to compromise and unauthorized modification.'
  desc 'check', "If the application owner and Authorizing Official have determined that encryption of data at rest is NOT required, this is not a finding.
 
One possible way to encrypt data within MariaDB is to use the file key management plugin. To determine if this is installed, check the following variables as the Database administrator:

MariaDB> SHOW PLUGINS; 

Confirm the file_key_management.so is listed.

MariaDB> SHOW GLOBAL VARIABLES LIKE 'file_key%';
MariaDB> SHOW GLOBAL VARIABLES LIKE 'aria_en%';
MariaDB> SHOW GLOBAL VARIABLES LIKE 'innodb_encrypt_tables';
MariaDB> SHOW GLOBAL VARIABLES LIKE 'innodb_encrypt_log';
MariaDB> SHOW GLOBAL VARIABLES LIKE 'innodb_tablespace%';
MariaDB> SHOW GLOBAL VARIABLES LIKE 'encrypt%';

Confirm these are ON.
 
If disk or filesystem requires encryption, ask the system owner, DBA, and SA to demonstrate the use of disk-level encryption. 

If this is required and is not found, this is a finding. 

If controls do not exist or are not enabled, this is a finding."
  desc 'fix', %q(MariaDB's data-at-rest encryption requires the use of a key management and encryption plugin. These plugins are responsible both for the management of encryption keys and for the actual encryption and decryption of data. MariaDB supports the use of multiple encryption keys. Each encryption key uses a 32-bit integer as a key identifier. If the specific plugin supports key rotation, then encryption keys can also be rotated, which creates a new version of the encryption key. 

The File Key Management plugin that ships with MariaDB is a key management and encryption plugin that reads encryption keys from a plain-text file. Although the plugin's shared library is distributed with MariaDB by default, the plugin is not installed by MariaDB by default. The plugin can be installed by providing the --plugin-load or the --plugin-load-add options. This can be specified as a command-line argument to mysqld or it can be specified in a relevant server option group in an option file. For example:
[mariadb]
...
plugin_load_add = file_key_management

Creating the Key File: To encrypt tables with encryption keys using the File Key Management plugin, first create the file that contains the encryption keys. The file must contain two pieces of information for each encryption key. First, each encryption key must be identified with a 32-bit integer as the key identifier. Second, the encryption key itself must be provided in hex-encoded form. These two pieces of information must be separated by a semicolon. 

For example, the file is formatted in the following way:
 <encryption_key_id1>;<hex-encoded_encryption_key1>
 <encryption_key_id2>;<hex-encoded_encryption_key2>

The key file can also be optionally encrypted to make it less accessible from the file system. That is explained further in the section below.

The File Key Management plugin uses Advanced Encryption Standard (AES) to encrypt data, which supports 128-bit, 192-bit, and 256-bit encryption keys. Therefore, the plugin also supports 128-bit, 192-bit, and 256-bit encryption keys.

Random encryption keys can be generated using the openssl rand command. For example, to create a random 256-bit (32-byte) encryption key, run the following command:

$ openssl rand -hex 32
a7addd9adea9978fda19f21e6be987880e68ac92632ca052e5bb42b1a506939a

Copy this encryption key to the key file using a text editor, or append a series of keys to a new key file. For example, to append three new encryption keys to a new key file, execute the following:

$ sudo openssl rand -hex 32 >> /etc/mysql/encryption/keyfile
$ sudo openssl rand -hex 32 >> /etc/mysql/encryption/keyfile
$ sudo openssl rand -hex 32 >> /etc/mysql/encryption/keyfile

The new key file would look something like the following after this step:

a7addd9adea9978fda19f21e6be987880e68ac92632ca052e5bb42b1a506939a
49c16acc2dffe616710c9ba9a10b94944a737de1beccb52dc1560abfdd67388b
8db1ee74580e7e93ab8cf157f02656d356c2f437d548d5bf16bf2a56932954a3

The key file still needs to have a key identifier for each encryption key added to the beginning of each line. Key identifiers do not need to be contiguous. Open the new key file in the preferred text editor and add the key identifiers. For example, the key file would look something like the following after this step:

1;a7addd9adea9978fda19f21e6be987880e68ac92632ca052e5bb42b1a506939a
2;49c16acc2dffe616710c9ba9a10b94944a737de1beccb52dc1560abfdd67388b
100;8db1ee74580e7e93ab8cf157f02656d356c2f437d548d5bf16bf2a56932954a3

The key identifiers give the user a way to reference the encryption keys from MariaDB. In the example above, encryption keys can be referenced using the key identifiers 1, 2, or 100 with the ENCRYPTION_KEY_ID table option or with system variables such as innodb_default_encryption_key_id. Multiple encryption keys are not always necessary; the encryption key with the key identifier "1" is the only mandatory encryption key.

Once the File Key Management Plugin is enabled, use it by creating an encrypted table:

CREATE TABLE t (i int) ENGINE=InnoDB ENCRYPTED=YES

Now, table t will be encrypted using the encryption key from the key file.)
  impact 0.7
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57162r841653_chk'
  tag severity: 'high'
  tag gid: 'V-253710'
  tag rid: 'SV-253710r841655_rule'
  tag stig_id: 'MADB-10-005200'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-57113r841654_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
