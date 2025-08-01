control 'SV-240325' do
  title 'The vRA PostgreSQL database must set log_connections to on.'
  desc 'For completeness of forensic analysis, it is necessary to track who/what (a user or other principal) logs on to the DBMS.'
  desc 'check', "At the command prompt, execute the following command:

# grep '^\\s*log_connections\\b' /storage/db/pgdata/postgresql.conf

If log_connections is not on, this is a finding."
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_connections TO 'on';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43558r668817_chk'
  tag severity: 'medium'
  tag gid: 'V-240325'
  tag rid: 'SV-240325r879874_rule'
  tag stig_id: 'VRAU-PG-000425'
  tag gtitle: 'SRG-APP-000503-DB-000350'
  tag fix_id: 'F-43517r668818_fix'
  tag 'documentable'
  tag legacy: ['SV-100077', 'V-89427']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
