control 'SV-240332' do
  title 'The vRA PostgreSQL database must set the log_statement to all.'
  desc 'Without tracking all or selected types of access to all or selected objects (tables, views, procedures, functions, etc.), it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

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
  tag check_id: 'C-43565r668838_chk'
  tag severity: 'medium'
  tag gid: 'V-240332'
  tag rid: 'SV-240332r879878_rule'
  tag stig_id: 'VRAU-PG-000460'
  tag gtitle: 'SRG-APP-000507-DB-000357'
  tag fix_id: 'F-43524r668839_fix'
  tag 'documentable'
  tag legacy: ['SV-100091', 'V-89441']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
