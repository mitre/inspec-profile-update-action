control 'SV-214091' do
  title 'PostgreSQL must generate audit records when unsuccessful attempts to delete categorized information (e.g., classification levels/security levels) occur.'
  desc 'Changes in categorized information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.

For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems.'
  desc 'check', 'First, as the database administrator, verify pgaudit is enabled by running the following SQL:

$ sudo su - postgres
$ psql -c "SHOW shared_preload_libraries"

If the output does not contain "pgaudit", this is a finding.

Next, verify that role, read, write, and ddl auditing are enabled:

$ psql -c "SHOW pgaudit.log"

If the output does not contain role, read, write, and ddl, this is a finding.'
  desc 'fix', "Note: The following instructions use the PGDATA and PGVER environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

All errors and denials are logged if logging is enabled. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging. 

Using pgaudit PostgreSQL can be configured to audit these requests. See supplementary content APPENDIX-B for documentation on installing pgaudit. 

With pgaudit installed the following configurations can be made: 

$ sudo su - postgres 
$ vi ${PGDATA?}/postgresql.conf 

Add the following parameters (or edit existing parameters): 

pgaudit.log='ddl, role, read, write' 

Now, as the system administrator, reload the server with the new configuration: 

# SYSTEMD SERVER ONLY 
$ sudo systemctl reload postgresql-${PGVER?}

# INITD SERVER ONLY 
$ sudo service postgresql-${PGVER?} reload"
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15307r360904_chk'
  tag severity: 'medium'
  tag gid: 'V-214091'
  tag rid: 'SV-214091r508027_rule'
  tag stig_id: 'PGS9-00-005000'
  tag gtitle: 'SRG-APP-000502-DB-000349'
  tag fix_id: 'F-15305r360905_fix'
  tag 'documentable'
  tag legacy: ['V-72931', 'SV-87583']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
