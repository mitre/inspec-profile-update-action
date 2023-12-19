control 'SV-100035' do
  title 'The vRA PostgreSQL database must have log collection enabled.'
  desc 'Without the ability to centrally manage the content captured in the audit records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

The content captured in audit records must be managed from a central location (necessitating automation). Centralized management of audit records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. 

The DBMS may write audit records to database tables, to files in the file system, to other kinds of local repository, or directly to a centralized log management system. Whatever the method used, it must be compatible with off-loading the records to the centralized system.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*logging_collector\b' /storage/db/pgdata/postgresql.conf

If "logging_collector" is not "on", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET logging_collector TO 'on';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x PostgreSQL'
  tag check_id: 'C-89077r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89385'
  tag rid: 'SV-100035r1_rule'
  tag stig_id: 'VRAU-PG-000280'
  tag gtitle: 'SRG-APP-000356-DB-000314'
  tag fix_id: 'F-96127r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001844']
  tag nist: ['AU-3 (2)']
end
