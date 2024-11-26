control 'SV-98971' do
  title 'The vROps PostgreSQL DB must generate audit records when unsuccessful attempts to delete security objects occur.'
  desc "The removal of security objects from the database/DBMS would seriously degrade a system's information assurance posture. If such an action is attempted, it must be logged.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones."
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_statement\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If "log_statement" is not set to "all", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_statement TO 'all';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-88013r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88321'
  tag rid: 'SV-98971r1_rule'
  tag stig_id: 'VROM-PG-000545'
  tag gtitle: 'SRG-APP-000501-DB-000337'
  tag fix_id: 'F-95063r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
