control 'SV-240315' do
  title 'The vRA PostgreSQL database must set the log_statement to all.'
  desc "Failed attempts to change the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized attempts to elevate or restrict individuals' and groups' privileges could go undetected. 

In an SQL environment, adding permissions is typically done via the GRANT command, or, in the negative, the DENY command. 

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones."
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_statement\b' /storage/db/pgdata/postgresql.conf

If "log_statement" is not "all", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_statement TO 'all';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43548r668787_chk'
  tag severity: 'medium'
  tag gid: 'V-240315'
  tag rid: 'SV-240315r879866_rule'
  tag stig_id: 'VRAU-PG-000360'
  tag gtitle: 'SRG-APP-000495-DB-000327'
  tag fix_id: 'F-43507r668788_fix'
  tag 'documentable'
  tag legacy: ['SV-100057', 'V-89407']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
