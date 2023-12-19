control 'SV-99981' do
  title 'The vRA PostgreSQL database must set the log_statement to all.'
  desc 'Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, it must be possible to configure auditing to do this. DBMSs typically make such information available through views or functions.

This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that the DBMS continually performs to determine if any and every action on the database is permitted.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_statement\b' /storage/db/pgdata/postgresql.conf

If "log_statement" is not "all", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_statement TO 'all';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x PostgreSQL'
  tag check_id: 'C-89023r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89331'
  tag rid: 'SV-99981r1_rule'
  tag stig_id: 'VRAU-PG-000030'
  tag gtitle: 'SRG-APP-000091-DB-000066'
  tag fix_id: 'F-96073r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
