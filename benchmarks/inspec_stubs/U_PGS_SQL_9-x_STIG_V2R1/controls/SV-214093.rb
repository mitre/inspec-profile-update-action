control 'SV-214093' do
  title 'PostgreSQL must generate audit records when security objects are deleted.'
  desc "The removal of security objects from the database/PostgreSQL would seriously degrade a system's information assurance posture. If such an event occurs, it must be logged."
  desc 'check', %q(Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.

First, as the database administrator (shown here as "postgres"), create a test table stig_test, enable row level security, and create a policy by running the following SQL:

$ sudo su - postgres
$ psql -c "CREATE TABLE stig_test(id INT)"
$ psql -c "ALTER TABLE stig_test ENABLE ROW LEVEL SECURITY"
$ psql -c "CREATE POLICY lock_table ON stig_test USING ('postgres' = current_user)"

Next, drop the policy and disable row level security:

$ psql -c "DROP POLICY lock_table ON stig_test"
$ psql -c "ALTER TABLE stig_test DISABLE ROW LEVEL SECURITY"

Now, as the database administrator (shown here as "postgres"), verify the security objects deletions were logged:

$ cat ${PGDATA?}/pg_log/<latest_log>
2016-03-30 14:54:18.991 EDT postgres postgres LOG: AUDIT: SESSION,11,1,DDL,DROP POLICY,,,DROP POLICY lock_table ON stig_test;,<none>
2016-03-30 14:54:42.373 EDT postgres postgres LOG: AUDIT: SESSION,12,1,DDL,ALTER TABLE,,,ALTER TABLE stig_test DISABLE ROW LEVEL SECURITY;,<none>

If audit records are not produced when security objects are dropped, this is a finding.)
  desc 'fix', "Note: The following instructions use the PGDATA and PGVER environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Using pgaudit PostgreSQL can be configured to audit these requests. See supplementary content APPENDIX-B for documentation on installing pgaudit. 

With pgaudit installed the following configurations can be made: 

$ sudo su - postgres 
$ vi ${PGDATA?}/postgresql.conf 

Add the following parameters (or edit existing parameters): 

pgaudit.log = 'ddl' 

Now, as the system administrator, reload the server with the new configuration: 

# SYSTEMD SERVER ONLY 
$ sudo systemctl reload postgresql-${PGVER?}

# INITD SERVER ONLY 
$ sudo service postgresql-${PGVER?} reload"
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15309r360910_chk'
  tag severity: 'medium'
  tag gid: 'V-214093'
  tag rid: 'SV-214093r508027_rule'
  tag stig_id: 'PGS9-00-005200'
  tag gtitle: 'SRG-APP-000501-DB-000336'
  tag fix_id: 'F-15307r360911_fix'
  tag 'documentable'
  tag legacy: ['V-72939', 'SV-87591']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
