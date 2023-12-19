control 'SV-253688' do
  title 'Database objects (including but not limited to tables, indexes, storage, stored procedures, functions, triggers, links to software external to MariaDB, etc.) must be owned by database/MariaDB principals authorized for ownership.'
  desc 'Within the database, object ownership implies full privileges to the owned object, including the privilege to assign access to the owned objects to other subjects. Database functions and procedures can be coded using definers rights. This allows anyone who uses the object to perform the actions if they were the owner. If not properly managed, this can lead to privileged actions being taken by unauthorized individuals.

Conversely, if critical tables or other objects rely on unauthorized owner accounts, these objects may be lost when an account is removed.'
  desc 'check', "Review system documentation to identify accounts authorized to have privileges against database objects. Review account privileges on objects in the database(s).
 
To show the list of system privileges that the MariaDB server supports, run:
MariaDB> SHOW PRIVILEGES;
 
Gather a list of SHOW GRANTS commands. SHOW GRANTS will list the privileges granted to the account.

Run this database query to create the SHOW GRANTS script for each user: 

MariaDB> SELECT DISTINCT CONCAT( 'SHOW GRANTS FOR ', user,'@', host,';') AS grantQuery FROM mysql.user WHERE is_role = 'N';

Run each SHOW GRANTS command for each user.

MariaDB> SHOW GRANTS FOR 'user'@'host';

Verify that all users have the correct privileges, if they do not, this is a finding.

Only DEFINERS of routines (functions and procedures) can change routines. To view the DEFINERS of all functions and procedures, as database administrator run the following SQL:
 
MariaDB>  SELECT * FROM mysql.proc \\G
 
Only DEFINERS of triggers can change triggers. To view all triggers and their DEFINERS, as database administrator run the following SQL: 

MariaDB>  SELECT * FROM information_schema.triggers \\G
 
If any database users are found to have unauthorized privileges on database objects, this is a finding."
  desc 'fix', 'Assign ownership of authorized objects to authorized object owner accounts.'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57140r841587_chk'
  tag severity: 'medium'
  tag gid: 'V-253688'
  tag rid: 'SV-253688r841589_rule'
  tag stig_id: 'MADB-10-002900'
  tag gtitle: 'SRG-APP-000133-DB-000200'
  tag fix_id: 'F-57091r841588_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
