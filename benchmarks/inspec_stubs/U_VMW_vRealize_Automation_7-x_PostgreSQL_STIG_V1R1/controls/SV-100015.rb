control 'SV-100015' do
  title 'vRA PostgreSQL database objects must only be accessible to the postgres account.'
  desc "Within the database, object ownership implies full privileges to the owned object, including the privilege to assign access to the owned objects to other subjects. Database functions and procedures can be coded using definer's rights. This allows anyone who utilizes the object to perform the actions if they were the owner. If not properly managed, this can lead to privileged actions being taken by unauthorized individuals.

Conversely, if critical tables or other objects rely on unauthorized owner accounts, these objects may be lost when an account is removed."
  desc 'check', 'At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "\\dp;"

Review the Access Privileges column.  

If any tables have permissions to users other than "postgres", this is a finding.'
  desc 'fix', 'At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER TABLE <tablename> OWNER TO postgres;"

Replace <tablename> with the name of the table discovered during the check.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x PostgreSQL'
  tag check_id: 'C-89057r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89365'
  tag rid: 'SV-100015r1_rule'
  tag stig_id: 'VRAU-PG-000135'
  tag gtitle: 'SRG-APP-000133-DB-000200'
  tag fix_id: 'F-96107r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
