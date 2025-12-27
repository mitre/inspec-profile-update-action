control 'SV-98935' do
  title 'The vROps PostgreSQL DB must provide an immediate real-time alert to appropriate support staff of all audit failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected. 

The appropriate support staff include, at a minimum, the ISSO and the DBA/SA.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*syslog_facility\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If "syslog_facility" is not set to "local0", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET syslog_facility TO 'local0';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-87977r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88285'
  tag rid: 'SV-98935r1_rule'
  tag stig_id: 'VROM-PG-000375'
  tag gtitle: 'SRG-APP-000360-DB-000320'
  tag fix_id: 'F-95027r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
