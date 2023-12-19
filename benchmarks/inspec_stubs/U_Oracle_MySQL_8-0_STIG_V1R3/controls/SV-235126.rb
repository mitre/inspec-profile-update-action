control 'SV-235126' do
  title 'The MySQL Database Server 8.0 must generate audit records when unsuccessful logons or connection attempts occur.'
  desc 'For completeness of forensic analysis, it is necessary to track failed attempts to log on to the Database Management System (DBMS). While positive identification may not be possible in a case of failed authentication, as much information as possible about the incident must be captured.'
  desc 'check', %q(Review the system documentation to determine if MySQL Server is required to audit when unsuccessful logons or connection attempts occur.

Check if MySQL audit is configured and enabled. The my.cnf file will set the variable audit_file.

To further check, execute the following query: 
SELECT PLUGIN_NAME, PLUGIN_STATUS
      FROM INFORMATION_SCHEMA.PLUGINS
      WHERE PLUGIN_NAME LIKE 'audit%';

The status of the audit_log plugin must be "active". If it is not "active", this is a finding.

Review audit filters and associated users by running the following queries:
SELECT `audit_log_filter`.`NAME`,
   `audit_log_filter`.`FILTER`
FROM `mysql`.`audit_log_filter`;

SELECT `audit_log_user`.`USER`,
   `audit_log_user`.`HOST`,
   `audit_log_user`.`FILTERNAME`
FROM `mysql`.`audit_log_user`;

All currently defined audits for the MySQL server instance will be listed. If no audits are returned, this is a finding.

To check if the audit filters that are in place are generating records when unsuccessful logons or connection attempts occur:

Log in to MySQL and then log out. For example, using MySQL Shell:
% mysqlsh —sql
 MySQL  SQL > \connect notauser@localhost
Creating a session to 'notauser@localhost'
Please provide the password for 'notauser@localhost': 
MySQL Error 1045: Access denied for user 'notauser'@'localhost' (using password: YES)

Review the audit log by running the Linux command:
Note, "status": 1045  for each indicates failed attempt.

sudo cat  <directory where audit log files are located>/audit.log | egrep notauser 
For example if the values returned by - "select @@datadir, @@audit_log_file; " are  /usr/local/mysql/data/,  audit.log
sudo cat  /usr/local/mysql/data/audit.log |egrep notauser

The audit data will look similar to the example below:
{ "timestamp": "2020-08-21 17:54:08", "id": 0, "class": "connection", "event": "connect", "connection_id": 20, "account": { "user": "", "host": "localhost" }, "login": { "user": "notauser", "os": "", "ip": "::1", "proxy": "" }, "connection_data": { "connection_type": "plugin", "status": 1045, "db": "" } },)
  desc 'fix', 'If currently required, configure the MySQL Database Server to audit when unsuccessful logons or connections attempts occur.

See the supplemental file "MySQL80Audit.sql".'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38345r623498_chk'
  tag severity: 'medium'
  tag gid: 'V-235126'
  tag rid: 'SV-235126r623500_rule'
  tag stig_id: 'MYS8-00-003900'
  tag gtitle: 'SRG-APP-000503-DB-000351'
  tag fix_id: 'F-38308r623499_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
