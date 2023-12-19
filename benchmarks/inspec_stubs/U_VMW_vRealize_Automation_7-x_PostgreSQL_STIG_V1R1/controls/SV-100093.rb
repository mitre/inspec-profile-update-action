control 'SV-100093' do
  title 'The vRA PostgreSQL database must set the log_statement to all.'
  desc 'In this context, direct access is any query, command, or call to the DBMS that comes from any source other than the application(s) that it supports. Examples would be the command line or a database management utility program. The intent is to capture all activity from administrative and non-standard sources.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_statement\b' /storage/db/pgdata/postgresql.conf

If "log_statement" is not "all", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_statement TO 'all';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x PostgreSQL'
  tag check_id: 'C-89135r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89443'
  tag rid: 'SV-100093r1_rule'
  tag stig_id: 'VRAU-PG-000465'
  tag gtitle: 'SRG-APP-000508-DB-000358'
  tag fix_id: 'F-96185r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
