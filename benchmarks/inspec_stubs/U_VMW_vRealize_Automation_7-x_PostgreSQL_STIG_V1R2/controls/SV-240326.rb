control 'SV-240326' do
  title 'The vRA PostgreSQL database must set the log_min_messages to warning.'
  desc 'For completeness of forensic analysis, it is necessary to track failed attempts to log on to the DBMS. While positive identification may not be possible in a case of failed authentication, as much information as possible about the incident must be captured.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_min_messages\b' /storage/db/pgdata/postgresql.conf

If "log_min_messages" is not "warning", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_min_messages TO 'warning';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43559r668820_chk'
  tag severity: 'medium'
  tag gid: 'V-240326'
  tag rid: 'SV-240326r879874_rule'
  tag stig_id: 'VRAU-PG-000430'
  tag gtitle: 'SRG-APP-000503-DB-000351'
  tag fix_id: 'F-43518r668821_fix'
  tag 'documentable'
  tag legacy: ['SV-100079', 'V-89429']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
