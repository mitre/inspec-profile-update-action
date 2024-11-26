control 'SV-239213' do
  title 'VMware Postgres must be configured to log to stderr.'
  desc 'Without the ability to centrally manage the content captured in the audit records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

The content captured in audit records must be managed from a central location (necessitating automation). Centralized management of audit records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records.

For VMware Postgres logs to be successfully sent to a remote log management system, log events must be sent to stderr. Those events will be captured and logged to disk, where they will be picked up by rsyslog for shipping.

'
  desc 'check', %q(At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SHOW log_destination;"|sed -n 3p|sed -e 's/^[ ]*//'

Expected result:

stderr

If the output does not match the expected result, this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_destination TO 'stderr';"

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 PostgreSQL'
  tag check_id: 'C-42446r679010_chk'
  tag severity: 'medium'
  tag gid: 'V-239213'
  tag rid: 'SV-239213r879732_rule'
  tag stig_id: 'VCPG-67-000021'
  tag gtitle: 'SRG-APP-000359-DB-000319'
  tag fix_id: 'F-42405r679011_fix'
  tag satisfies: ['SRG-APP-000359-DB-000319', 'SRG-APP-000515-DB-000318']
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
