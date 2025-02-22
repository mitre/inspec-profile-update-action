control 'SV-239821' do
  title 'The vROps PostgreSQL DB must generate audit records when privileges/permissions are deleted.'
  desc "Changes in the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized elevation or restriction of individuals' and groups' privileges could go undetected. Elevated privileges give users access to information and functionality that they should not have; restricted privileges wrongly deny access to authorized users.

In an SQL environment, deleting permissions is typically done via the REVOKE or DENY command."
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_statement\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If "log_statement" is not set to "all", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_statement TO 'all';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-43054r663838_chk'
  tag severity: 'medium'
  tag gid: 'V-239821'
  tag rid: 'SV-239821r879870_rule'
  tag stig_id: 'VROM-PG-000530'
  tag gtitle: 'SRG-APP-000499-DB-000330'
  tag fix_id: 'F-43013r663839_fix'
  tag 'documentable'
  tag legacy: ['SV-98965', 'V-88315']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
