control 'SV-240319' do
  title 'The DBMS must generate audit records when unsuccessful attempts to modify security objects occur.'
  desc 'Changes in the database objects (tables, views, procedures, functions) that record and control permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized changes to the security subsystem could go undetected. The database could be severely compromised or rendered inoperative.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_statement\b' /storage/db/pgdata/postgresql.conf

If "log_statement" is not all, this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_statement TO 'all';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43552r668799_chk'
  tag severity: 'medium'
  tag gid: 'V-240319'
  tag rid: 'SV-240319r879867_rule'
  tag stig_id: 'VRAU-PG-000380'
  tag gtitle: 'SRG-APP-000496-DB-000335'
  tag fix_id: 'F-43511r668800_fix'
  tag 'documentable'
  tag legacy: ['SV-100065', 'V-89415']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
