control 'SV-240279' do
  title 'The vRA PostgreSQL database must set the log_statement to all.'
  desc "Session auditing is for use when a user's activities are under investigation. To be sure of capturing all activity during those periods when session auditing is in use, it needs to be in operation for the whole time the DBMS is running."
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_statement\b' /storage/db/pgdata/postgresql.conf

If "log_statement" is not "all", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_statement TO 'all';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43512r668679_chk'
  tag severity: 'medium'
  tag gid: 'V-240279'
  tag rid: 'SV-240279r879562_rule'
  tag stig_id: 'VRAU-PG-000040'
  tag gtitle: 'SRG-APP-000092-DB-000208'
  tag fix_id: 'F-43471r668680_fix'
  tag 'documentable'
  tag legacy: ['SV-99983', 'V-89333']
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
