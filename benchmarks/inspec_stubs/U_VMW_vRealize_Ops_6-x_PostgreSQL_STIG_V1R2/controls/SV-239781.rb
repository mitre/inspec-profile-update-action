control 'SV-239781' do
  title 'The vROps PostgreSQL DB must produce audit records containing sufficient information to establish the outcome (success or failure) of the events.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the system.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the information system after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_line_prefix\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If log_line_prefix is not set to "%m %d %u %r %p %l %c", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_line_prefix TO '%m %d %u %r %p %l %c';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-43014r663718_chk'
  tag severity: 'medium'
  tag gid: 'V-239781'
  tag rid: 'SV-239781r879567_rule'
  tag stig_id: 'VROM-PG-000075'
  tag gtitle: 'SRG-APP-000099-DB-000043'
  tag fix_id: 'F-42973r663719_fix'
  tag 'documentable'
  tag legacy: ['SV-98885', 'V-88235']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
