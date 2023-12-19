control 'SV-240341' do
  title 'The vRA PostgreSQL database must have log collection enabled.'
  desc "If the configuration of the DBMS's auditing is spread across multiple locations in the database management software, or across multiple commands, only loosely related, it is harder to use and takes longer to reconfigure in response to events.

The DBMS must provide a unified tool for audit configuration."
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*logging_collector\b' /storage/db/pgdata/postgresql.conf

If "logging_collector" is not "on", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET logging_collector TO 'on';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43574r668865_chk'
  tag severity: 'medium'
  tag gid: 'V-240341'
  tag rid: 'SV-240341r879729_rule'
  tag stig_id: 'VRAU-PG-000595'
  tag gtitle: 'SRG-APP-000356-DB-000315'
  tag fix_id: 'F-43533r668866_fix'
  tag 'documentable'
  tag legacy: ['SV-100109', 'V-89459']
  tag cci: ['CCI-001844']
  tag nist: ['AU-3 (2)']
end
