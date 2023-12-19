control 'SV-253689' do
  title 'The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, links to software external to the MariaDB, etc.) must be restricted to authorized users.'
  desc 'If the MariaDB were to allow any user to make changes to database structure or logic, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', "Gather a list of SHOW GRANTS commands. This list will include users and roles: 

MariaDB> SELECT DISTINCT CONCAT( 'SHOW GRANTS FOR ', user,'@', host,';') AS grantQuery FROM mysql.user;

Run each SHOW GRANTS commands and verify that all objects have the correct privileges, if they do not, this is a finding.

MariaDB> SHOW GRANTS FOR 'user'@'host';

Find the data directory and verify its operating system privileges. 

MariaDB> SHOW GLOBAL VARIABLES LIKE '%datadir%';

# ls -al /path/to/datadir

If permissions of the database directory are not limited to an authorized user account, this is a finding."
  desc 'fix', 'As the database administrator, revoke any permissions from a role that are deemed unnecessary by running the following SQL:

MariaDB> REVOKE  PERMISSION FROM ROLE_NAME ;

Revoke any roles from a user if they are deemed unnecessary by running the following SQL:

MariaDB> REVOKE  ROLE_NAME  FROM  test_user ;
 
If the revoked role is the default role for the user, the REVOKE command should be followed by a command to set a new default role that has appropriate permissions, or no default role:

MariaDB> SET DEFAULT ROLE NONE FOR  test_user ;
MariaDB> SET DEFAULT ROLE  ROLE_NAME  for  test_user ;'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57141r841590_chk'
  tag severity: 'medium'
  tag gid: 'V-253689'
  tag rid: 'SV-253689r841860_rule'
  tag stig_id: 'MADB-10-003000'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag fix_id: 'F-57092r841591_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
