control 'SV-239833' do
  title 'The vROps PostgreSQL DB must generate audit records when unsuccessful accesses to objects occur.'
  desc 'Without tracking all or selected types of access to all or selected objects (tables, views, procedures, functions, etc.), it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

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
  tag check_id: 'C-43066r663874_chk'
  tag severity: 'medium'
  tag gid: 'V-239833'
  tag rid: 'SV-239833r879878_rule'
  tag stig_id: 'VROM-PG-000595'
  tag gtitle: 'SRG-APP-000507-DB-000357'
  tag fix_id: 'F-43025r663875_fix'
  tag 'documentable'
  tag legacy: ['SV-98989', 'V-88339']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
