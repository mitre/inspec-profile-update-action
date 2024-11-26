control 'SV-24835' do
  title 'Credentials used to access remote databases should be protected by encryption and restricted to authorized users.'
  desc 'Access to database connection credential stores provides easy access to the database. Unauthorized access to the database can result without controls in place to prevent unauthorized access to the credentials.'
  desc 'check', %q(Review the System Security Plan to discover any external storage of passwords used by applications, batch jobs or users to connect to the database.

If no database passwords or credentials are stored outside of the database including use of Oracle Wallets and the Oracle password file (pwd*.ora or orapwd*.ora), this check is Not a Finding.  

View the sqlnet.ora file to determine if Oracle Wallets are used for authentication.

If the "WALLET_LOCATION" entry exists in the file, then view permissions on the directory and contents.

If access to this directory and these files is not restricted to the Oracle database and listener services, DBA's, and other authorized system and administrative accounts this is a Finding.

From SQL*Plus:

  select value from v$parameter where name = 'remote_login_passwordfile';

If the command returns the value NONE, this is not a Finding.

If it returns the value SHARED, this is a Finding.

If it returns the value EXCLUSIVE, view access permissions to the Oracle password file.

The default name for Windows is pwd[SID].ora and is located in the ORACLE_HOME\database directory.

On UNIX hosts, the file is named orapw[SID] and stored in the $ORACLE_HOME/dbs directory.

If access to this file is not restricted to the Oracle database, DBA's, and other authorized system and administrative accounts, this is a Finding.

For other password or credential stores, interview the DBA to ask what restrictions to the storage location of passwords have been assigned.

If accounts other than those that require access to the storage location have been granted permissions, this is a Finding.)
  desc 'fix', 'Consider alternate methods for database connections to avoid custom storage of local connection credentials.

Develop and document use of locally stored credentials and their authorized use and access in the System Security Plan.

Restrict access and use of the credentials to authorized users using host file permissions and any other available method to restrict access.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29397r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15659'
  tag rid: 'SV-24835r1_rule'
  tag stig_id: 'DG0191-ORACLE11'
  tag gtitle: 'DBMS credential protection'
  tag fix_id: 'F-26422r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
