control 'SV-214089' do
  title 'PostgreSQL must generate audit records when unsuccessful attempts to modify security objects occur.'
  desc 'Changes in the database objects (tables, views, procedures, functions) that record and control permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized changes to the security subsystem could go undetected. The database could be severely compromised or rendered inoperative.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', %q(Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.

As the database administrator (shown here as "postgres"), create a test role by running the following SQL:

$ sudo su - postgres
$ psql -c "CREATE ROLE bob"

Next, to test if audit records are generated from unsuccessful attempts at modifying security objects, run the following SQL:

$ sudo su - postgres
$ psql -c "SET ROLE bob; UPDATE pg_authid SET rolsuper = 't' WHERE rolname = 'bob';"

Next, as the database administrator (shown here as "postgres"), verify that the denials were logged:

$ sudo su - postgres
$ cat ${PGDATA?}/pg_log/<latest_log>
< 2016-03-17 10:34:00.017 EDT bob 56eabf52.b62 postgres: >ERROR: permission denied for relation pg_authid
< 2016-03-17 10:34:00.017 EDT bob 56eabf52.b62 postgres: >STATEMENT: UPDATE pg_authid SET rolsuper = 't' WHERE rolname = 'bob';

If denials are not logged, this is a finding.)
  desc 'fix', 'Configure PostgreSQL to produce audit records when unsuccessful attempts to modify security objects occur.

Unsuccessful attempts to modifying security objects can be logged if logging is enabled. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.'
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15305r360898_chk'
  tag severity: 'medium'
  tag gid: 'V-214089'
  tag rid: 'SV-214089r508027_rule'
  tag stig_id: 'PGS9-00-004800'
  tag gtitle: 'SRG-APP-000496-DB-000335'
  tag fix_id: 'F-15303r360899_fix'
  tag 'documentable'
  tag legacy: ['SV-87579', 'V-72927']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
