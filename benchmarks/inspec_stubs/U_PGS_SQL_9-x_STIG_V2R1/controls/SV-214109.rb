control 'SV-214109' do
  title 'PostgreSQL must generate audit records when unsuccessful attempts to modify privileges/permissions occur.'
  desc 'Failed attempts to change the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized attempts to elevate or restrict privileges could go undetected.

Modifying permissions is done via the GRANT and REVOKE commands.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', %q(First, as the database administrator (shown here as "postgres"), create a role 'bob' and a test table by running the following SQL: 

$ sudo su - postgres 
$ psql -c "CREATE ROLE bob; CREATE TABLE test(id INT)" 

Next, set current role to bob and attempt to modify privileges: 

$ psql -c "SET ROLE bob; GRANT ALL PRIVILEGES ON test TO bob;" 
$ psql -c "SET ROLE bob; REVOKE ALL PRIVILEGES ON test FROM bob;" 

Now, as the database administrator (shown here as "postgres"), verify the unsuccessful attempt was logged: 

$ sudo su - postgres 
$ cat ${PGDATA?}/pg_log/<latest_log> 
2016-07-14 18:12:23.208 EDT postgres postgres ERROR: permission denied for relation test 
2016-07-14 18:12:23.208 EDT postgres postgres STATEMENT: GRANT ALL PRIVILEGES ON test TO bob; 
2016-07-14 18:14:52.895 EDT postgres postgres ERROR: permission denied for relation test 
2016-07-14 18:14:52.895 EDT postgres postgres STATEMENT: REVOKE ALL PRIVILEGES ON test FROM bob; 

If audit logs are not generated when unsuccessful attempts to modify privileges/permissions occur, this is a finding.)
  desc 'fix', 'Configure PostgreSQL to produce audit records when unsuccessful attempts to modify privileges occur.

All denials are logged by default if logging is enabled. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.'
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15325r360958_chk'
  tag severity: 'medium'
  tag gid: 'V-214109'
  tag rid: 'SV-214109r508027_rule'
  tag stig_id: 'PGS9-00-006800'
  tag gtitle: 'SRG-APP-000495-DB-000329'
  tag fix_id: 'F-15323r360959_fix'
  tag 'documentable'
  tag legacy: ['SV-87627', 'V-72975']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
