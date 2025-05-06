control 'SV-233573' do
  title 'PostgreSQL must generate audit records when security objects are modified.'
  desc 'Changes in the database objects (tables, views, procedures, functions) that record and control permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized changes to the security subsystem could go undetected. The database could be severely compromised or rendered inoperative.'
  desc 'check', 'First, as the database administrator, verify pgaudit is enabled by running the following SQL:

$ sudo su - postgres
$ psql -c "SHOW shared_preload_libraries"

If the results does not contain pgaudit, this is a finding.

Next, verify that role, read, write, and ddl auditing are enabled:

$ psql -c "SHOW pgaudit.log"

If the output does not contain role, read, write, and ddl, this is a finding.

Next, verify that accessing the catalog is audited by running the following SQL:

$ psql -c "SHOW pgaudit.log_catalog"

If log_catalog is not on, this is a finding.'
  desc 'fix', "Note: The following instructions use the PGDATA and PGVER environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

Using pgaudit the DBMS (PostgreSQL) can be configured to audit these requests. See supplementary content APPENDIX-B for documentation on installing pgaudit.

With pgaudit installed, the following configurations can be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log_catalog = 'on'
pgaudit.log='ddl, role, read, write'

Next, as the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}"
  impact 0.5
  ref 'DPMS Target Crunchy Data PostgreSQL'
  tag check_id: 'C-36767r606942_chk'
  tag severity: 'medium'
  tag gid: 'V-233573'
  tag rid: 'SV-233573r617333_rule'
  tag stig_id: 'CD12-00-006600'
  tag gtitle: 'SRG-APP-000496-DB-000334'
  tag fix_id: 'F-36732r606943_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
