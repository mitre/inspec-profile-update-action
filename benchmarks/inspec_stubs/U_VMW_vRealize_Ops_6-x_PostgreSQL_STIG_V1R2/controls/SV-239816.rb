control 'SV-239816' do
  title 'The vROps PostgreSQL DB must generate audit records when unsuccessful attempts to add privileges/permissions occur.'
  desc "Failed attempts to change the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized attempts to elevate or restrict individuals' and groups' privileges could go undetected. 

In an SQL environment, adding permissions is typically done via the GRANT command, or, in the negative, the DENY command. 

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones."
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_statement\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If "log_statement" is not set to "all", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_statement TO 'all';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-43049r663823_chk'
  tag severity: 'medium'
  tag gid: 'V-239816'
  tag rid: 'SV-239816r879866_rule'
  tag stig_id: 'VROM-PG-000495'
  tag gtitle: 'SRG-APP-000495-DB-000327'
  tag fix_id: 'F-43008r663824_fix'
  tag 'documentable'
  tag legacy: ['SV-98955', 'V-88305']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
