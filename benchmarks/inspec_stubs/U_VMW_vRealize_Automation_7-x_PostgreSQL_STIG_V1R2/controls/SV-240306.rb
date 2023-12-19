control 'SV-240306' do
  title 'The vRA PostgreSQL database must be configured to use a syslog facility.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected. 

The appropriate support staff include, at a minimum, the ISSO and the DBA/SA.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*logging_collector\b' /storage/db/pgdata/postgresql.conf

If "logging_collector" is not "on", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET logging_collector TO 'on';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43539r668760_chk'
  tag severity: 'medium'
  tag gid: 'V-240306'
  tag rid: 'SV-240306r668762_rule'
  tag stig_id: 'VRAU-PG-000295'
  tag gtitle: 'VRAU-PG-000295'
  tag fix_id: 'F-43498r668761_fix'
  tag 'documentable'
  tag legacy: ['SV-100039', 'V-89389']
  tag cci: ['CCI-001888']
  tag nist: ['AU-8 b']
end
