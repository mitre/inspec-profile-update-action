control 'SV-214094' do
  title 'PostgreSQL must generate audit records when unsuccessful attempts to retrieve privileges/permissions occur.'
  desc 'Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, it must be possible to configure auditing to do this. PostgreSQLs typically make such information available through views or functions.

This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that PostgreSQL continually performs to determine if any and every action on the database is permitted.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', %q(Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.

First, as the database administrator (shown here as "postgres"), create a role 'bob' by running the following SQL:

$ sudo su - postgres
$ psql -c "CREATE ROLE bob"

Next, attempt to retrieve information from the pg_authid table:

$ psql -c "SET ROLE bob; SELECT * FROM pg_authid"

Now, as the database administrator (shown here as "postgres"), verify the event was logged in pg_log:

$ sudo su - postgres
$ cat ${PGDATA?}/pg_log/<latest_log>
< 2016-07-13 16:49:58.864 EDT postgres postgres ERROR: > permission denied for relation pg_authid
< 2016-07-13 16:49:58.864 EDT postgres postgres STATEMENT: > SELECT * FROM pg_authid;

If the above steps cannot verify that audit records are produced when PostgreSQL denies retrieval of privileges/permissions/role memberships, this is a finding.)
  desc 'fix', 'Configure PostgreSQL to produce audit records when unsuccessful attempts to access privileges occur.

All denials are logged if logging is enabled. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.'
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15310r360913_chk'
  tag severity: 'medium'
  tag gid: 'V-214094'
  tag rid: 'SV-214094r508027_rule'
  tag stig_id: 'PGS9-00-005300'
  tag gtitle: 'SRG-APP-000091-DB-000325'
  tag fix_id: 'F-15308r360914_fix'
  tag 'documentable'
  tag legacy: ['SV-87593', 'V-72941']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
