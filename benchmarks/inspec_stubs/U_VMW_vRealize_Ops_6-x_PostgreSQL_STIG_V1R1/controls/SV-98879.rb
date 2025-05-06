control 'SV-98879' do
  title 'The vROps PostgreSQL DB must produce audit records containing time stamps to establish when the events occurred.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events relating to an incident.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know the date and time when events occurred.

Associating the date and time with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application. 

Database software is capable of a range of actions on data stored within the database. It is important, for accurate forensic analysis, to know exactly when specific actions were performed. This requires the date and time an audit record is referring to. If date and time information is not recorded and stored with the audit record, the record itself is of very limited use.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_line_prefix\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If log_line_prefix is not set to "%m %d %u %r %p %l %c", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_line_prefix TO '%m %d %u %r %p %l %c';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-87921r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88229'
  tag rid: 'SV-98879r1_rule'
  tag stig_id: 'VROM-PG-000060'
  tag gtitle: 'SRG-APP-000096-DB-000040'
  tag fix_id: 'F-94971r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
