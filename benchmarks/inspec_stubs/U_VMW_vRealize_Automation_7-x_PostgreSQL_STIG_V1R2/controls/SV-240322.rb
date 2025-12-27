control 'SV-240322' do
  title 'The vRA PostgreSQL database must set the log_statement to all.'
  desc "The removal of security objects from the database/DBMS would seriously degrade a system's information assurance posture. If such an event occurs, it must be logged."
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_statement\b' /storage/db/pgdata/postgresql.conf

If "log_statement" is not all, this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_statement TO 'all';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43555r668808_chk'
  tag severity: 'medium'
  tag gid: 'V-240322'
  tag rid: 'SV-240322r879872_rule'
  tag stig_id: 'VRAU-PG-000405'
  tag gtitle: 'SRG-APP-000501-DB-000336'
  tag fix_id: 'F-43514r668809_fix'
  tag 'documentable'
  tag legacy: ['SV-100071', 'V-89421']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
