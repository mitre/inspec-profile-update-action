control 'SV-99997' do
  title 'vRA PostgreSQL database log file data must contain required data elements.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.

Identifiers (if authenticated or otherwise known) include, but are not limited to, user database tables, primary key values, user names, or process identifiers.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_line_prefix\b' /storage/db/pgdata/postgresql.conf

If "log_line_prefix" is not set to "%m %d %u %r %p %l %c", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_line_prefix TO '%m %d %u %r %p %l %c';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x PostgreSQL'
  tag check_id: 'C-89039r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89347'
  tag rid: 'SV-99997r1_rule'
  tag stig_id: 'VRAU-PG-000075'
  tag gtitle: 'SRG-APP-000100-DB-000201'
  tag fix_id: 'F-96089r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
