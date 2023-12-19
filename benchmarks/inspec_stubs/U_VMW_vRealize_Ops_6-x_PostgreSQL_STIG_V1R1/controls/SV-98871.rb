control 'SV-98871' do
  title 'The vROps PostgreSQL DB must be able to generate audit records when privileges/permissions are retrieved.'
  desc 'Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, it must be possible to configure auditing to do this. DBMSs typically make such information available through views or functions.

This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that the DBMS continually performs to determine if any and every action on the database is permitted.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_statement\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If log_statement is not set to "all", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_statement TO 'all';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-87913r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88221'
  tag rid: 'SV-98871r1_rule'
  tag stig_id: 'VROM-PG-000035'
  tag gtitle: 'SRG-APP-000091-DB-000066'
  tag fix_id: 'F-94963r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
