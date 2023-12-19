control 'SV-240282' do
  title 'vRA PostgreSQL database log file data must contain required data elements.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events relating to an incident.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as application components, modules, session identifiers, filenames, host names, and functionality. 

Associating information about where the event occurred within the application provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_line_prefix\b' /storage/db/pgdata/postgresql.conf

If "log_line_prefix" is not set to "%m %d %u %r %p %l %c", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_line_prefix TO '%m %d %u %r %p %l %c';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43515r668688_chk'
  tag severity: 'medium'
  tag gid: 'V-240282'
  tag rid: 'SV-240282r879565_rule'
  tag stig_id: 'VRAU-PG-000060'
  tag gtitle: 'SRG-APP-000097-DB-000041'
  tag fix_id: 'F-43474r668689_fix'
  tag 'documentable'
  tag legacy: ['SV-99991', 'V-89341']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
