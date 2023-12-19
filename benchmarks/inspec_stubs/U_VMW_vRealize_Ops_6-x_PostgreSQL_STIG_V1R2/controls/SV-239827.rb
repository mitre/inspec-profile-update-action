control 'SV-239827' do
  title 'The vROps PostgreSQL DB must generate audit records when unsuccessful logons or connection attempts occur.'
  desc 'For completeness of forensic analysis, it is necessary to track failed attempts to log on to the DBMS. While positive identification may not be possible in a case of failed authentication, as much information as possible about the incident must be captured.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_min_messages\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If "log_min_messages" is not set to "warning", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_min_messages TO 'warning';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-43060r663856_chk'
  tag severity: 'medium'
  tag gid: 'V-239827'
  tag rid: 'SV-239827r879874_rule'
  tag stig_id: 'VROM-PG-000565'
  tag gtitle: 'SRG-APP-000503-DB-000351'
  tag fix_id: 'F-43019r663857_fix'
  tag 'documentable'
  tag legacy: ['SV-98977', 'V-88327']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
