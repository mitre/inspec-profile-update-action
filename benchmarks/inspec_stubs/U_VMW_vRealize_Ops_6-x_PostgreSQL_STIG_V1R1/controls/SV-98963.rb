control 'SV-98963' do
  title 'The vROps PostgreSQL DB must generate audit records when unsuccessful attempts to modify security objects occur.'
  desc 'Changes in the database objects (tables, views, procedures, functions) that record and control permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized changes to the security subsystem could go undetected. The database could be severely compromised or rendered inoperative.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_statement\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If "log_statement" is not set to "all", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_statement TO 'all';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-88005r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88313'
  tag rid: 'SV-98963r1_rule'
  tag stig_id: 'VROM-PG-000515'
  tag gtitle: 'SRG-APP-000496-DB-000335'
  tag fix_id: 'F-95055r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
