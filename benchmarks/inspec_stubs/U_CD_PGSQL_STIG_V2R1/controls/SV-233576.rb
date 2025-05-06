control 'SV-233576' do
  title 'PostgreSQL must generate audit records when unsuccessful attempts to add privileges/permissions occur.'
  desc 'Failed attempts to change the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized attempts to elevate or restrict privileges could go undetected.

In a SQL environment, adding permissions is typically done via the GRANT command, or, in the negative, the REVOKE command.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', 'Note: The following instructions use the PGDATA and PGLOG environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for PGLOG.

First, as the database administrator (shown here as "postgres"), create a role "bob" and a test table by running the following SQL:

$ sudo su - postgres
$ psql -c "CREATE ROLE bob; CREATE TABLE test(id INT);"

Next, set current role to "bob" and attempt to modify privileges:

$ psql -c "SET ROLE bob; GRANT ALL PRIVILEGES ON test TO bob;"

Next, as the database administrator (shown here as "postgres"), verify the unsuccessful attempt was logged:

$ sudo su - postgres
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
2016-07-14 18:12:23.208 EDT postgres postgres ERROR: permission denied for relation test
2016-07-14 18:12:23.208 EDT postgres postgres STATEMENT: GRANT ALL PRIVILEGES ON test TO bob;

If audit logs are not generated when unsuccessful attempts to add privileges/permissions occur, this is a finding.'
  desc 'fix', 'Configure PostgreSQL to produce audit records when unsuccessful attempts to add privileges occur.

All denials are logged by default if logging is enabled. To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.'
  impact 0.5
  ref 'DPMS Target Crunchy Data PostgreSQL'
  tag check_id: 'C-36770r606951_chk'
  tag severity: 'medium'
  tag gid: 'V-233576'
  tag rid: 'SV-233576r606953_rule'
  tag stig_id: 'CD12-00-006900'
  tag gtitle: 'SRG-APP-000495-DB-000327'
  tag fix_id: 'F-36735r606952_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
