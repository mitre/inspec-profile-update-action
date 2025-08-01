control 'SV-239813' do
  title 'The vROps PostgreSQL DB must be able to generate audit records when security objects are accessed.'
  desc 'Changes to the security configuration must be tracked.

This requirement applies to situations where security data is retrieved or modified via data manipulation operations, as opposed to via specialized security functionality.

In an SQL environment, types of access include, but are not necessarily limited to:
SELECT
INSERT
UPDATE
DELETE
EXECUTE'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_statement\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If "log_statement" is not set to "all", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_statement TO 'all';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-43046r663814_chk'
  tag severity: 'medium'
  tag gid: 'V-239813'
  tag rid: 'SV-239813r879863_rule'
  tag stig_id: 'VROM-PG-000470'
  tag gtitle: 'SRG-APP-000492-DB-000332'
  tag fix_id: 'F-43005r663815_fix'
  tag 'documentable'
  tag legacy: ['SV-98949', 'V-88299']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
