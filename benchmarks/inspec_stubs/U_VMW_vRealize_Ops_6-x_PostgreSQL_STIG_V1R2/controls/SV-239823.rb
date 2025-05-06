control 'SV-239823' do
  title 'The vROps PostgreSQL DB must generate audit records when security objects are deleted.'
  desc "The removal of security objects from the database/DBMS would seriously degrade a system's information assurance posture. If such an event occurs, it must be logged."
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_statement\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If "log_statement" is not set to "all", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_statement TO 'all';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-43056r663844_chk'
  tag severity: 'medium'
  tag gid: 'V-239823'
  tag rid: 'SV-239823r879872_rule'
  tag stig_id: 'VROM-PG-000540'
  tag gtitle: 'SRG-APP-000501-DB-000336'
  tag fix_id: 'F-43015r663845_fix'
  tag 'documentable'
  tag legacy: ['SV-98969', 'V-88319']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
