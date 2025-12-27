control 'SV-224158' do
  title 'Database objects (including but not limited to tables, indexes, storage, stored procedures, functions, triggers, links to software external to the EDB Postgres Advanced Server, etc.) must be owned by database/EDB Postgres Advanced Server principals authorized for ownership.'
  desc "Within the database, object ownership implies full privileges to the owned object, including the privilege to assign access to the owned objects to other subjects. Database functions and procedures can be coded using definer's rights. This allows anyone who utilizes the object to perform the actions if they were the owner. If not properly managed, this can lead to privileged actions being taken by unauthorized individuals.

Conversely, if critical tables or other objects rely on unauthorized owner accounts, these objects may be lost when an account is removed."
  desc 'check', 'Review system documentation to identify accounts authorized to own database objects. Review accounts that own objects in the database(s) by running this SQL command:

select * from sys.all_objects;

If any database objects are found to be owned by users not authorized to own database objects, this is a finding.'
  desc 'fix', 'Assign ownership of authorized objects to authorized object owner accounts by running this SQL command for each object to be changed:

ALTER <type> <object name> OWNER TO <new owner>;

For example: ALTER TABLE my_table OWNER TO APP_USER;'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25831r495494_chk'
  tag severity: 'medium'
  tag gid: 'V-224158'
  tag rid: 'SV-224158r508023_rule'
  tag stig_id: 'EP11-00-003500'
  tag gtitle: 'SRG-APP-000133-DB-000200'
  tag fix_id: 'F-25819r495495_fix'
  tag 'documentable'
  tag legacy: ['V-100343', 'SV-109447']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
