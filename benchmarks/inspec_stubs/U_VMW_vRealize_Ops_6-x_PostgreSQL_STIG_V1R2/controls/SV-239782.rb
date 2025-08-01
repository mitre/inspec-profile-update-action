control 'SV-239782' do
  title 'The vROps PostgreSQL DB must produce audit records containing sufficient information to establish the identity of any user/subject or process associated with the event.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.

Identifiers (if authenticated or otherwise known) include, but are not limited to, user database tables, primary key values, user names, or process identifiers.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_line_prefix\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If log_line_prefix is not set to "%m %d %u %r %p %l %c", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_line_prefix TO '%m %d %u %r %p %l %c';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-43015r663721_chk'
  tag severity: 'medium'
  tag gid: 'V-239782'
  tag rid: 'SV-239782r879568_rule'
  tag stig_id: 'VROM-PG-000080'
  tag gtitle: 'SRG-APP-000100-DB-000201'
  tag fix_id: 'F-42974r663722_fix'
  tag 'documentable'
  tag legacy: ['SV-98887', 'V-88237']
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
