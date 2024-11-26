control 'SV-99985' do
  title 'The vRA PostgreSQL database must set the log_statement to all.'
  desc "Without the capability to capture, record, and log all content related to a user session, investigations into suspicious user activity would be hampered.

Typically, this DBMS capability would be used in conjunction with comparable monitoring of a user's online session, involving other software components such as operating systems, web servers and front-end user applications. The current requirement, however, deals specifically with the DBMS."
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_statement\b' /storage/db/pgdata/postgresql.conf

If "log_statement" is not "all", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_statement TO 'all';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x PostgreSQL'
  tag check_id: 'C-89027r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89335'
  tag rid: 'SV-99985r1_rule'
  tag stig_id: 'VRAU-PG-000045'
  tag gtitle: 'SRG-APP-000093-DB-000052'
  tag fix_id: 'F-96077r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001462']
  tag nist: ['AU-14 (2)']
end
