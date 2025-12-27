control 'SV-240321' do
  title 'The vRA PostgreSQL database must set the log_statement to all.'
  desc "Failed attempts to change the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized attempts to elevate or restrict individuals' and groups' privileges could go undetected. 

In an SQL environment, deleting permissions is typically done via the REVOKE or DENY command. 

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones."
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_statement\b' /storage/db/pgdata/postgresql.conf

If "log_statement is not all", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_statement TO 'all';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43554r668805_chk'
  tag severity: 'medium'
  tag gid: 'V-240321'
  tag rid: 'SV-240321r879870_rule'
  tag stig_id: 'VRAU-PG-000400'
  tag gtitle: 'SRG-APP-000499-DB-000331'
  tag fix_id: 'F-43513r668806_fix'
  tag 'documentable'
  tag legacy: ['SV-100069', 'V-89419']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
