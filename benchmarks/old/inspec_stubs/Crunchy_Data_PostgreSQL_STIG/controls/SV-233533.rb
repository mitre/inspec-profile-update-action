control 'SV-233533' do
  title 'PostgreSQL must reveal detailed error messages only to the ISSO, ISSM, SA, and DBA.'
  desc %q(If PostgreSQL provides too much information in error logs and administrative messages to the screen, this could lead to compromise. The structure and content of error messages need to be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements. 

Some default PostgreSQL error messages can contain information that could aid an attacker in, among others things, identifying the database type, host address, or state of the database. Custom errors may contain sensitive customer information. 

It is important that detailed error messages be visible only to those who are authorized to view them; that general users receive only generalized acknowledgment that errors have occurred; and that these generalized messages appear only when relevant to the user's task. For example, a message along the lines of, "An error has occurred. Unable to save your changes. If this problem persists, please contact your help desk." would be relevant. A message such as "Warning: your transaction generated a large number of page splits." would likely not be relevant. 

Administrative users authorized to review detailed error messages typically are the ISSO, ISSM, SA, and DBA. Other individuals or roles may be specified according to organization-specific needs, with DBA approval.)
  desc 'check', %q(Note: The following instructions use the PGDATA and PGLOG environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for instructions on configuring PGLOG.

Check PostgreSQL settings and custom database code to determine if detailed error messages are ever displayed to unauthorized individuals.

To check the level of detail for errors exposed to clients, as the DBA (shown here as "postgres"), run the following:

$ sudo su - postgres
$ psql -c "SHOW client_min_messages;"

If client_min_messages is set to LOG or DEBUG, this is a finding.

If detailed error messages are displayed to individuals not authorized to view them, this is a finding.

#### stderr Logging

Logs may contain detailed information and should only be accessible by the database owner.

As the database administrator, verify the following settings of logs.

Note: Consult the organization's documentation on acceptable log privileges.

$ sudo su - postgres
$ psql -c "SHOW log_file_mode;" 

Next, verify the log files have the set configurations.

$ ls -l ${PGLOG?}
total 32
-rw-------. 1 postgres postgres 0 Apr 8 00:00 postgresql-Fri.log
-rw-------. 1 postgres postgres 8288 Apr 11 17:36 postgresql-Mon.log
-rw-------. 1 postgres postgres 0 Apr 9 00:00 postgresql-Sat.log
-rw-------. 1 postgres postgres 0 Apr 10 00:00 postgresql-Sun.log
-rw-------. 1 postgres postgres 16212 Apr 7 17:05 postgresql-Thu.log
-rw-------. 1 postgres postgres 1130 Apr 6 17:56 postgresql-Wed.log

If logs are not owned by the database administrator or have permissions that are not 0600, this is a finding.

#### syslog Logging

If PostgreSQL is configured to use syslog for logging, consult organization location and permissions for syslog log files. If the logs are not owned by root or have permissions that are not 0600, this is a finding.)
  desc 'fix', 'Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.

To set the level of detail for error messages exposed to clients, as the DBA (shown here as "postgres"), run the following commands:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
client_min_messages = error'
  impact 0.5
  ref 'DPMS Target Crunchy Data PostgreSQL'
  tag check_id: 'C-36727r606822_chk'
  tag severity: 'medium'
  tag gid: 'V-233533'
  tag rid: 'SV-233533r606824_rule'
  tag stig_id: 'CD12-00-002500'
  tag gtitle: 'SRG-APP-000267-DB-000163'
  tag fix_id: 'F-36692r606823_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
