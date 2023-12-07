control 'SV-224165' do
  title 'The EDB Postgres Advanced Server must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following:

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and
(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'Verify that the pg_hba.conf is not using the "trust" authentication method.

Note that the default location for the pg_hba.conf file is in the postgresql data directory. The location of the pg_hba.conf file for a running postgres instance can be found using the following command run from a Windows command prompt:

 psql -d <database name> -U <database superuser name> -c "SHOW hba_file"

where, <database name> is any database in the EDB postgres instance and <database superuser name> is a database superuser. By default, a database named "edb" and a superuser named "enterprisedb" are installed with EDB Postgres Advanced Server (EPAS).

To verify that the pg_hba.conf file is not using the methods listed above, open the pg_hba.conf file in a text editor and inspect the contents of the file. If any uncommented lines have "trust" specified for the "METHOD" column and the setting has not been documented with sufficient justification and approved, this is a finding.

Optionally, the following command can be run from a Windows command prompt to identify any uncommented lines in the pg_hba.conf file that may be using these methods: 

 type <postgresql data directory>\\pg_hba.conf | findstr /N "trust" | find /V /N "#"

Note: For the command above, if the path to the pg_hba.conf file contains spaces in it, the path to the file (including the file name) should be placed in double quotes. 

If any uncommented lines showing that the "trust" authentication method has been specified are reported via the above command and the setting has not been documented with sufficient justification and approved, this is a finding.'
  desc 'fix', 'Open "<postgresql data directory>\\pg_hba.conf" in an editor. 

Note that the default location for the pg_hba.conf file is in the postgresql data directory. The location of the pg_hba.conf file for a running postgres instance can be found using the following command run from a Windows command prompt:

 psql -d <database name> -U <database superuser name> -c "SHOW hba_file"

where, <database name> is any database in the EDB postgres instance and <database superuser name> is a database superuser. By default, a database named "edb" and a superuser named "enterprisedb" are installed with EDB Postgres Advanced Server (EPAS).

If any rows have "trust" specified for the "METHOD" column that are not documented and approved, delete the rows or change them to other authentication methods.

Permitted methods in preferred order are: peer (local only), cert, ldap, sspi, pam, sha-256-scram, md5'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25838r495513_chk'
  tag severity: 'medium'
  tag gid: 'V-224165'
  tag rid: 'SV-224165r508023_rule'
  tag stig_id: 'EP11-00-004200'
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag fix_id: 'F-25826r495514_fix'
  tag 'documentable'
  tag legacy: ['SV-109461', 'V-100357']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
