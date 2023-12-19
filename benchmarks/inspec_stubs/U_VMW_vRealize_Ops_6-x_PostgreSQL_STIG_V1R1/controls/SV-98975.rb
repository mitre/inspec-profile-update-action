control 'SV-98975' do
  title 'The vROps PostgreSQL DB must generate audit records when successful logons or connections occur.'
  desc 'For completeness of forensic analysis, it is necessary to track who/what (a user or other principal) logs on to the DBMS.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_connections\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If "log_connections" is not set to "on", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_connections TO 'on';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-88017r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88325'
  tag rid: 'SV-98975r1_rule'
  tag stig_id: 'VROM-PG-000560'
  tag gtitle: 'SRG-APP-000503-DB-000350'
  tag fix_id: 'F-95067r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
