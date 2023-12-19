control 'SV-253700' do
  title 'MariaDB must enforce authorized access to all PKI private keys stored/used by the DBMS.'
  desc "The DoD standard for authentication is DoD-approved PKI certificates. PKI certificate-based authentication is performed by requiring the certificate holder to cryptographically prove possession of the corresponding private key.

If the private key is stolen, an attacker can use the private key(s) to impersonate the certificate holder. In cases where the MariaDB-stored private keys are used to authenticate MariaDB to the system's clients, loss of the corresponding private keys would allow an attacker to successfully perform undetected man in the middle attacks against the MariaDB system and its clients.

Both the holder of a digital certificate and the issuing authority must take careful measures to protect the corresponding private key. Private keys should always be generated and protected in FIPS 140-2 validated cryptographic modules.

All access to the private key(s) of MariaDB must be restricted to authorized and authenticated users. If unauthorized users have access to one or more of the MariaDB s private keys, an attacker could gain access to the key(s) and use them to impersonate the database on the network or otherwise perform unauthorized actions."
  desc 'check', "First, as the database administrator, verify the following settings: Note: If no specific directory given before the filename, the files are stored in DATADIR.
 
MariaDB> SHOW GLOBAL VARIABLES LIKE 'ssl_ca';
MariaDB> SHOW GLOBAL VARIABLES LIKE 'ssl_cert';
MariaDB> SHOW GLOBAL VARIABLES LIKE 'ssl_key';
MariaDB> SHOW GLOBAL VARIABLES LIKE 'ssl_crlpath';
MariaDB> SHOW GLOBAL VARIABLES LIKE 'datadir';

Verify the permissions of the above files. 

Example:

ls -al /path/to/ssl_cert 

MariaDB Enterprise Server runs as the mysql operating system user, thus should be owned by user mysql and group mysql with user read and group read file level permissions. 

Example: 

-r-------.  1 mysql
 
If the files and directories are not properly secured, this is a finding."
  desc 'fix', 'If the SSL files are not secured properly in the file system, change the ownership and permissions with operating system operations. 

Example: 

chown mysql:mysql /path/to/file
chmod 440 /path/to/file'
  impact 0.7
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57152r841623_chk'
  tag severity: 'high'
  tag gid: 'V-253700'
  tag rid: 'SV-253700r841625_rule'
  tag stig_id: 'MADB-10-004100'
  tag gtitle: 'SRG-APP-000176-DB-000068'
  tag fix_id: 'F-57103r841624_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
