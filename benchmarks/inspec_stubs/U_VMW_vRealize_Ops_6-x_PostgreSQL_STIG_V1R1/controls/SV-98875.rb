control 'SV-98875' do
  title 'The vROps PostgreSQL DB must provide authorized users to capture, record, and log all content related to a user session.'
  desc "Without the capability to capture, record, and log all content related to a user session, investigations into suspicious user activity would be hampered.

Typically, this DBMS capability would be used in conjunction with comparable monitoring of a user's online session, involving other software components such as operating systems, web servers, and front-end user applications. The current requirement, however, deals specifically with the DBMS."
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_statement\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If log_statement is not set to "all", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_statement TO 'all';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-87917r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88225'
  tag rid: 'SV-98875r1_rule'
  tag stig_id: 'VROM-PG-000050'
  tag gtitle: 'SRG-APP-000093-DB-000052'
  tag fix_id: 'F-94967r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001462']
  tag nist: ['AU-14 (2)']
end
