control 'SV-240314' do
  title 'The vRA PostgreSQL database must set the log_statement to all.'
  desc "Changes in the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized elevation or restriction of individuals' and groups' privileges could go undetected. Elevated privileges give users access to information and functionality that they should not have; restricted privileges wrongly deny access to authorized users.

In an SQL environment, adding permissions is typically done via the GRANT command, or, in the negative, the DENY command."
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_statement\b' /storage/db/pgdata/postgresql.conf

If "log_statement" is not "all", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_statement TO 'all';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43547r668784_chk'
  tag severity: 'medium'
  tag gid: 'V-240314'
  tag rid: 'SV-240314r879866_rule'
  tag stig_id: 'VRAU-PG-000355'
  tag gtitle: 'SRG-APP-000495-DB-000326'
  tag fix_id: 'F-43506r668785_fix'
  tag 'documentable'
  tag legacy: ['SV-100055', 'V-89405']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
