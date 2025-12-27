control 'SV-100101' do
  title 'The vRA PostgreSQL database must be configured to use a syslog facility.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity. 

The DBMS may write audit records to database tables, to files in the file system, to other kinds of local repository, or directly to a centralized log management system. Whatever the method used, it must be compatible with off-loading the records to the centralized system.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*syslog_facility\b' /storage/db/pgdata/postgresql.conf

If "syslog_facility" is not "local0", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET syslog_facility TO 'local0';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x PostgreSQL'
  tag check_id: 'C-89143r2_chk'
  tag severity: 'medium'
  tag gid: 'V-89451'
  tag rid: 'SV-100101r1_rule'
  tag stig_id: 'VRAU-PG-000485'
  tag gtitle: 'SRG-APP-000515-DB-000318'
  tag fix_id: 'F-96193r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
