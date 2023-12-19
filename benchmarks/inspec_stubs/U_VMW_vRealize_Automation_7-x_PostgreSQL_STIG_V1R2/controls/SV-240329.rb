control 'SV-240329' do
  title 'The vRA PostgreSQL database must set log_connections to on.'
  desc "For completeness of forensic analysis, it is necessary to know how long a user's (or other principal's) connection to the DBMS lasts. This can be achieved by recording disconnections, in addition to logons/connections, in the audit logs. 

Disconnection may be initiated by the user or forced by the system (as in a timeout) or result from a system or network failure. To the greatest extent possible, all disconnections must be logged."
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_connections\b' /storage/db/pgdata/postgresql.conf

If "log_connections" is not "on", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_connections TO 'on';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43562r668829_chk'
  tag severity: 'medium'
  tag gid: 'V-240329'
  tag rid: 'SV-240329r879876_rule'
  tag stig_id: 'VRAU-PG-000445'
  tag gtitle: 'SRG-APP-000505-DB-000352'
  tag fix_id: 'F-43521r668830_fix'
  tag 'documentable'
  tag legacy: ['SV-100085', 'V-89435']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
