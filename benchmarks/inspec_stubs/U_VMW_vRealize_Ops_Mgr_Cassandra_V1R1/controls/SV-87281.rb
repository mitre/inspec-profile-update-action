control 'SV-87281' do
  title 'Database objects (including but not limited to tables, indexes, storage, stored procedures, functions, triggers, links to software external to the DBMS, etc.) must be owned by database/DBMS principals authorized for ownership.'
  desc "Within the database, object ownership implies full privileges to the owned object, including the privilege to assign access to the owned objects to other subjects. Database functions and procedures can be coded using definer's rights. This allows anyone who utilizes the object to perform the actions if they were the owner. If not properly managed, this can lead to privileged actions being taken by unauthorized individuals.

Conversely, if critical tables or other objects rely on unauthorized owner accounts, these objects may be lost when an account is removed."
  desc 'check', 'Review system documentation to identify accounts authorized to own database objects. Review accounts that own objects in the database(s).

If any database objects are found to be owned by users not authorized to own database objects, this is a finding.

Open cqlsh prompt in the Cassandra Server and type "LIST ALL PERMISSIONS;" command.  Review the list of access privileges available. 

If all the objects are owned by superuser account (cassandra in default Cassandra Server configuration), this is not a finding. 

Otherwise, it is a finding.'
  desc 'fix', 'Assign ownership of authorized objects to authorized object owner accounts.

Open cqlsh prompt in the Cassandra Server and run "REVOKE <list of permissions> ON <tablename> FROM <current owner user account name>; GRANT ALL PERMISSIONS ON <tablename> TO <superuser account name>;"'
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72805r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72649'
  tag rid: 'SV-87281r1_rule'
  tag stig_id: 'VROM-CS-000105'
  tag gtitle: 'SRG-APP-000133-DB-000200'
  tag fix_id: 'F-79053r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
