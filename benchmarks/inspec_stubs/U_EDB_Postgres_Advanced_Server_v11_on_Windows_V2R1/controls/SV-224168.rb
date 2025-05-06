control 'SV-224168' do
  title 'If passwords are used for authentication, the EDB Postgres Advanced Server must transmit only encrypted representations of passwords.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

In such cases, passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission.

DBMS passwords sent in clear text format across the network are vulnerable to discovery by unauthorized users. Disclosure of passwords may easily lead to unauthorized access to the database.'
  desc 'check', 'Verify that the pg_hba.conf is not using the "password" authentication method.

Note that the default location for the pg_hba.conf file is in the postgresql data directory. The location of the pg_hba.conf file for a running postgres instance can be found using the following command run from a Windows command prompt:

 psql -d <database name> -U <database superuser name> -c "SHOW hba_file"

where, <database name> is any database in the EDB postgres instance and <database superuser name> is a database superuser. By default, a database named "edb" and a superuser named "enterprisedb" are installed with EDB Postgres Advanced Server (EPAS).

To verify that the pg_hba.conf file is not using the methods listed above, open the pg_hba.conf file in a text editor and inspect the contents of the file. If any uncommented lines have "password" specified for the "METHOD" column, this is a finding.

Optionally, the following command can be run from a Windows command prompt to identify any uncommented lines in the pg_hba.conf file that may be using these methods: 

 type <postgresql data directory>\\pg_hba.conf | findstr /N "password" | find /V /N "#"

Note: For the command above, if the path to the pg_hba.conf file contains spaces in it, the path to the file (including the file name) should be placed in double quotes. 

If any uncommented lines showing that the "password" authentication method has been specified are reported via the above command, this is a finding.'
  desc 'fix', 'Open "<postgresql data directory>\\pg_hba.conf" in an editor. 

Note that the default location for the pg_hba.conf file is in the postgresql data directory. The location of the pg_hba.conf file for a running postgres instance can be found using the following command run from a Windows command prompt:

 psql -d <database name> -U <database superuser name> -c "SHOW hba_file"

where, <database name> is any database in the EDB postgres instance and <database superuser name> is a database superuser. By default, a database named "edb" and a superuser named "enterprisedb" are installed with EDB Postgres Advanced Server (EPAS).

For any rows that have "password" specified for the "METHOD" column, change the value to "sha-256-scram" or "md5".'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25841r495522_chk'
  tag severity: 'medium'
  tag gid: 'V-224168'
  tag rid: 'SV-224168r508023_rule'
  tag stig_id: 'EP11-00-004400'
  tag gtitle: 'SRG-APP-000172-DB-000075'
  tag fix_id: 'F-25829r495523_fix'
  tag 'documentable'
  tag legacy: ['SV-109467', 'V-100363']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
