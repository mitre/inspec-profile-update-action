control 'SV-98873' do
  title 'The vROps PostgreSQL DB must initiate session auditing upon startup.'
  desc "Session auditing is for use when a user's activities are under investigation. To be sure of capturing all activity during those periods when session auditing is in use, it needs to be in operation for the whole time the DBMS is running."
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_statement\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If log_statement is not set to "all", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_statement TO 'all';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-87915r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88223'
  tag rid: 'SV-98873r1_rule'
  tag stig_id: 'VROM-PG-000045'
  tag gtitle: 'SRG-APP-000092-DB-000208'
  tag fix_id: 'F-94965r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
