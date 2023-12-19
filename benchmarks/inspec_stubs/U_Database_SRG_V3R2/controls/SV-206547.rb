control 'SV-206547' do
  title 'Database objects (including but not limited to tables, indexes, storage, stored procedures, functions, triggers, links to software external to the DBMS, etc.) must be owned by database/DBMS principals authorized for ownership.'
  desc "Within the database, object ownership implies full privileges to the owned object, including the privilege to assign access to the owned objects to other subjects. Database functions and procedures can be coded using definer's rights. This allows anyone who utilizes the object to perform the actions if they were the owner. If not properly managed, this can lead to privileged actions being taken by unauthorized individuals.

Conversely, if critical tables or other objects rely on unauthorized owner accounts, these objects may be lost when an account is removed."
  desc 'check', 'Review system documentation to identify accounts authorized to own database objects. Review accounts that own objects in the database(s).

If any database objects are found to be owned by users not authorized to own database objects, this is a finding.'
  desc 'fix', 'Assign ownership of authorized objects to authorized object owner accounts.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6807r291309_chk'
  tag severity: 'medium'
  tag gid: 'V-206547'
  tag rid: 'SV-206547r617447_rule'
  tag stig_id: 'SRG-APP-000133-DB-000200'
  tag gtitle: 'SRG-APP-000133'
  tag fix_id: 'F-6807r291310_fix'
  tag 'documentable'
  tag legacy: ['SV-42749', 'V-32412']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
