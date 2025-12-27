control 'SV-240313' do
  title 'The vRA PostgreSQL database must set the log_statement to all.'
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

# grep '^\s*log_statement\b' /storage/db/pgdata/postgresql.conf

If "log_statement" is not "all", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_statement TO 'all';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43546r668781_chk'
  tag severity: 'medium'
  tag gid: 'V-240313'
  tag rid: 'SV-240313r879863_rule'
  tag stig_id: 'VRAU-PG-000340'
  tag gtitle: 'SRG-APP-000492-DB-000333'
  tag fix_id: 'F-43505r668782_fix'
  tag 'documentable'
  tag legacy: ['SV-100053', 'V-89403']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
