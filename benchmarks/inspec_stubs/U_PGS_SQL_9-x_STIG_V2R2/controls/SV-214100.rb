control 'SV-214100' do
  title 'PostgreSQL must generate audit records when unsuccessful attempts to access categorized information (e.g., classification levels/security levels) occur.'
  desc 'Changes in categorized information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.

For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems.'
  desc 'check', 'First, as the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -c "SHOW pgaudit.log"

If pgaudit.log does not contain, "ddl, write, role", this is a finding.'
  desc 'fix', "Note: The following instructions use the PGDATA and PGVER environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Configure PostgreSQL to produce audit records when unsuccessful attempts to access categories of information. 

All denials are logged if logging is enabled. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging. 

With pgaudit installed the following configurations can be made: 

$ sudo su - postgres 
$ vi ${PGDATA?}/postgresql.conf 

Add the following parameters (or edit existing parameters): 

pgaudit.log = 'ddl, write, role' 

Now, as the system administrator, reload the server with the new configuration: 

# SYSTEMD SERVER ONLY 
$ sudo systemctl reload postgresql-${PGVER?}

# INITD SERVER ONLY 
$ sudo service postgresql-${PGVER?} reload"
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15316r360931_chk'
  tag severity: 'medium'
  tag gid: 'V-214100'
  tag rid: 'SV-214100r508027_rule'
  tag stig_id: 'PGS9-00-005900'
  tag gtitle: 'SRG-APP-000494-DB-000345'
  tag fix_id: 'F-15314r360932_fix'
  tag 'documentable'
  tag legacy: ['SV-87607', 'V-72955']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
