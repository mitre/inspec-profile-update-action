control 'SV-214106' do
  title 'PostgreSQL must generate audit records when unsuccessful attempts to execute privileged activities or other system-level access occur.'
  desc 'Without tracking privileged activity, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

System documentation should include a definition of the functionality considered privileged.

A privileged function in this context is any operation that modifies the structure of the database, its built-in logic, or its security settings. This would include all Data Definition Language (DDL) statements and all security-related statements. In an SQL environment, it encompasses, but is not necessarily limited to:

CREATE
ALTER
DROP
GRANT
REVOKE

Note: That it is particularly important to audit, and tightly control, any action that weakens the implementation of this requirement itself, since the objective is to have a complete audit trail of all administrative activity.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', 'As the database administrator (shown here as "postgres"), create the role bob by running the following SQL:

$ sudo su - postgres
$ psql -c "CREATE ROLE bob"

Next, change the current role to bob and attempt to execute privileged activity:

$ psql -c "CREATE ROLE stig_test SUPERUSER"
$ psql -c "CREATE ROLE stig_test CREATEDB"
$ psql -c "CREATE ROLE stig_test CREATEROLE"
$ psql -c "CREATE ROLE stig_test CREATEUSER"

Now, as the database administrator (shown here as "postgres"), verify that an audit event was produced (use the latest log):

$ sudo su - postgres
$ cat ${PGDATA?}/pg_log/<latest_log>
< 2016-02-23 20:16:32.396 EST postgres 56cfa74f.79eb postgres: >ERROR: must be superuser to create superusers
< 2016-02-23 20:16:32.396 EST postgres 56cfa74f.79eb postgres: >STATEMENT: CREATE ROLE stig_test SUPERUSER;
< 2016-02-23 20:16:48.725 EST postgres 56cfa74f.79eb postgres: >ERROR: permission denied to create role
< 2016-02-23 20:16:48.725 EST postgres 56cfa74f.79eb postgres: >STATEMENT: CREATE ROLE stig_test CREATEDB;
< 2016-02-23 20:16:54.365 EST postgres 56cfa74f.79eb postgres: >ERROR: permission denied to create role
< 2016-02-23 20:16:54.365 EST postgres 56cfa74f.79eb postgres: >STATEMENT: CREATE ROLE stig_test CREATEROLE;
< 2016-02-23 20:17:05.949 EST postgres 56cfa74f.79eb postgres: >ERROR: must be superuser to create superusers
< 2016-02-23 20:17:05.949 EST postgres 56cfa74f.79eb postgres: >STATEMENT: CREATE ROLE stig_test CREATEUSER;

If audit records are not produced, this is a finding.'
  desc 'fix', 'Configure PostgreSQL to produce audit records when unsuccessful attempts to execute privileged SQL.

All denials are logged by default if logging is enabled. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.'
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15322r360949_chk'
  tag severity: 'medium'
  tag gid: 'V-214106'
  tag rid: 'SV-214106r508027_rule'
  tag stig_id: 'PGS9-00-006500'
  tag gtitle: 'SRG-APP-000504-DB-000355'
  tag fix_id: 'F-15320r360950_fix'
  tag 'documentable'
  tag legacy: ['V-72969', 'SV-87621']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
