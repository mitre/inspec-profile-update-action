control 'SV-214074' do
  title 'Database objects (including but not limited to tables, indexes, storage, trigger procedures, functions, links to software external to PostgreSQL, etc.) must be owned by database/DBMS principals authorized for ownership.'
  desc "Within the database, object ownership implies full privileges to the owned object, including the privilege to assign access to the owned objects to other subjects. Database functions and procedures can be coded using definer's rights. This allows anyone who utilizes the object to perform the actions if they were the owner. If not properly managed, this can lead to privileged actions being taken by unauthorized individuals.

Conversely, if critical tables or other objects rely on unauthorized owner accounts, these objects may be lost when an account is removed."
  desc 'check', 'Review system documentation to identify accounts authorized to own database objects. Review accounts that own objects in the database(s).

If any database objects are found to be owned by users not authorized to own database objects, this is a finding.

To check the ownership of objects in the database, as the database administrator, run the following SQL:

$ sudo su - postgres
$ psql -x -c "\\dn *.*"
$ psql -x -c "\\dt *.*"
$ psql -x -c "\\ds *.*"
$ psql -x -c "\\dv *.*"
$ psql -x -c "\\df+ *.*"

If any object is not owned by an authorized role for ownership, this is a finding.'
  desc 'fix', 'Assign ownership of authorized objects to authorized object owner accounts. 

#### Schema Owner 

To create a schema owned by the user bob, run the following SQL: 

$ sudo su - postgres 
$ psql -c "CREATE SCHEMA test AUTHORIZATION bob" 

To alter the ownership of an existing object to be owned by the user bob, run the following SQL: 

$ sudo su - postgres 
$ psql -c "ALTER SCHEMA test OWNER TO bob"'
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15290r360853_chk'
  tag severity: 'medium'
  tag gid: 'V-214074'
  tag rid: 'SV-214074r508027_rule'
  tag stig_id: 'PGS9-00-003100'
  tag gtitle: 'SRG-APP-000133-DB-000200'
  tag fix_id: 'F-15288r360854_fix'
  tag 'documentable'
  tag legacy: ['SV-87549', 'V-72897']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
