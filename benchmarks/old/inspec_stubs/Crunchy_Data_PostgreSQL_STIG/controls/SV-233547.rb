control 'SV-233547' do
  title 'PostgreSQL must produce audit records of its enforcement of access restrictions associated with changes to the configuration of PostgreSQL or database(s).'
  desc 'Without auditing the enforcement of access restrictions against changes to configuration, it would be difficult to identify attempted attacks and an audit trail would not be available for forensic investigation for after-the-fact actions.

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.'
  desc 'check', %q(Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for PGLOG.

To verify that system denies are logged when unprivileged users attempt to change database configuration, as the database administrator (shown here as "postgres"), run the following commands:

$ sudo su - postgres
$ psql

Next, create a role with no privileges, change the current role to that user and attempt to change a configuration by running the following SQL:

CREATE ROLE bob;
SET ROLE bob;
SET pgaudit.role='test';
RESET ROLE;
DROP ROLE bob;

Now check ${PGLOG?} (use the latest log):

$ cat ${PGDATA?}/${PGLOG?}/postgresql-Thu.log
< 2016-01-28 17:57:34.092 UTC bob postgres: >ERROR: permission denied to set parameter "pgaudit.role"
< 2016-01-28 17:57:34.092 UTC bob postgres: >STATEMENT: SET pgaudit.role='test';

If the denial is not logged, this is a finding.

By default PostgreSQL configuration files are owned by the postgres user and cannot be edited by non-privileged users:

$ ls -la ${PGDATA?} | grep postgresql.conf
-rw-------. 1 postgres postgres 21758 Jan 22 10:27 postgresql.conf

If postgresql.conf is not owned by the database owner and does not have read and write permissions for the owner, this is a finding.)
  desc 'fix', 'Enable logging.

All denials are logged by default if logging is enabled. To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.'
  impact 0.5
  ref 'DPMS Target Crunchy Data PostgreSQL'
  tag check_id: 'C-36741r606864_chk'
  tag severity: 'medium'
  tag gid: 'V-233547'
  tag rid: 'SV-233547r606866_rule'
  tag stig_id: 'CD12-00-004100'
  tag gtitle: 'SRG-APP-000381-DB-000361'
  tag fix_id: 'F-36706r606865_fix'
  tag 'documentable'
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
