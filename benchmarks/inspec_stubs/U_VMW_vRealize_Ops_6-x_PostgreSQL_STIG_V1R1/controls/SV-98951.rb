control 'SV-98951' do
  title 'The vROps PostgreSQL DB must generate audit records when unsuccessful attempts to access security objects occur.'
  desc 'Changes to the security configuration must be tracked.

This requirement applies to situations where security data is retrieved or modified via data manipulation operations, as opposed to via specialized security functionality.

In an SQL environment, types of access include, but are not necessarily limited to:
SELECT
INSERT
UPDATE
DELETE
EXECUTE

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_statement\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If "log_statement" is not set to "all", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_statement TO 'all';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-87993r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88301'
  tag rid: 'SV-98951r1_rule'
  tag stig_id: 'VROM-PG-000475'
  tag gtitle: 'SRG-APP-000492-DB-000333'
  tag fix_id: 'F-95043r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
