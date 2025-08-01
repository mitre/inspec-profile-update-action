control 'SV-214098' do
  title 'PostgreSQL must generate audit records when unsuccessful accesses to objects occur.'
  desc 'Without tracking all or selected types of access to all or selected objects (tables, views, procedures, functions, etc.), it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

In an SQL environment, types of access include, but are not necessarily limited to:

SELECT
INSERT
UPDATE
DROP
EXECUTE

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', %q(Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.

First, as the database administrator (shown here as "postgres"), create a schema, test_schema, create a table, test_table, within test_schema, and insert a value:

$ sudo su - postgres
$ psql -c "CREATE SCHEMA test_schema"
$ psql -c "CREATE TABLE test_schema.test_table(id INT)"
$ psql -c "INSERT INTO test_schema.test_table(id) VALUES (0)"

Next, create a role 'bob' and attempt to SELECT, INSERT, UPDATE, and DROP from the test table: 

$ psql -c "CREATE ROLE BOB"
$ psql -c "SET ROLE bob; SELECT * FROM test_schema.test_table"

$ psql -c "SET ROLE bob; INSERT INTO test_schema.test_table VALUES (0)"
$ psql -c "SET ROLE bob; UPDATE test_schema.test_table SET id = 1 WHERE id = 0"
$ psql -c "SET ROLE bob; DROP TABLE test_schema.test_table"
$ psql -c "SET ROLE bob; DROP SCHEMA test_schema"

Now, as the database administrator (shown here as "postgres"), review PostgreSQL/database security and audit settings to verify that audit records are created for unsuccessful attempts at the specified access to the specified objects:

$ sudo su - postgres
$ cat ${PGDATA?}/pg_log/<latest_log>
2016-03-30 17:23:41.254 EDT postgres postgres ERROR: permission denied for schema test_schema at character 15
2016-03-30 17:23:41.254 EDT postgres postgres STATEMENT: SELECT * FROM test_schema.test_table;
2016-03-30 17:23:53.973 EDT postgres postgres ERROR: permission denied for schema test_schema at character 13
2016-03-30 17:23:53.973 EDT postgres postgres STATEMENT: INSERT INTO test_schema.test_table VALUES (0);
2016-03-30 17:24:32.647 EDT postgres postgres ERROR: permission denied for schema test_schema at character 8
2016-03-30 17:24:32.647 EDT postgres postgres STATEMENT: UPDATE test_schema.test_table SET id = 1 WHERE id = 0;
2016-03-30 17:24:46.197 EDT postgres postgres ERROR: permission denied for schema test_schema
2016-03-30 17:24:46.197 EDT postgres postgres STATEMENT: DROP TABLE test_schema.test_table;
2016-03-30 17:24:51.582 EDT postgres postgres ERROR: must be owner of schema test_schema
2016-03-30 17:24:51.582 EDT postgres postgres STATEMENT: DROP SCHEMA test_schema;

If any of the above steps did not create audit records for SELECT, INSERT, UPDATE, and DROP, this is a finding.)
  desc 'fix', 'Configure PostgreSQL to produce audit records when unsuccessful attempts to access objects occur.

All errors and denials are logged if logging is enabled. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.'
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15314r360925_chk'
  tag severity: 'medium'
  tag gid: 'V-214098'
  tag rid: 'SV-214098r508027_rule'
  tag stig_id: 'PGS9-00-005700'
  tag gtitle: 'SRG-APP-000507-DB-000357'
  tag fix_id: 'F-15312r360926_fix'
  tag 'documentable'
  tag legacy: ['SV-87603', 'V-72951']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
