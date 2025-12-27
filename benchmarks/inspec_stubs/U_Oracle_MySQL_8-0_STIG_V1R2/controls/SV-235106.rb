control 'SV-235106' do
  title 'The MySQL Database Server 8.0 must be able to generate audit records when unsuccessful attempts to retrieve privileges/permissions occur.'
  desc 'Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, it must be possible to configure auditing to do this. Database Management Systems (DBMSs) typically make such information available through views or functions.

This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of  privileges/permissions/role memberships that the DBMS continually performs to determine if any and every action on the database is permitted.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', %q(Review the system documentation to determine if MySQL Server is required to audit when unsuccessful attempts to retrieve privileges/permissions occur.

Check if MySQL audit is configured and enabled. The my.cnf file will set the variable audit_file.

To further check, execute the following query:
SELECT PLUGIN_NAME, PLUGIN_STATUS
      FROM INFORMATION_SCHEMA.PLUGINS
      WHERE PLUGIN_NAME LIKE 'audit%';

The status of the audit_log plugin should be "active". If it is not "active", this is a finding.

Review audit filters and associated users by running the following queries:
SELECT `audit_log_filter`.`NAME`,
   `audit_log_filter`.`FILTER`
FROM `mysql`.`audit_log_filter`;

SELECT `audit_log_user`.`USER`,
   `audit_log_user`.`HOST`,
   `audit_log_user`.`FILTERNAME`
FROM `mysql`.`audit_log_user`;

All currently defined audits for the MySQL server instance will be listed. If no audits are returned, this is a finding.

To check if the audit filters that are in place are generating records to audit when unsuccessful attempts to retrieve privileges/permissions occur, run the following query using a user that does not have privileges so that it fails:
select * from mysql.proxies_priv;
ERROR: 1142: SELECT command denied to user 'auditme'@'localhost' for table 'proxies_priv'

Review the audit log by running the command:
sudo cat  <directory where audit log files are located>/audit.log|egrep proxies_priv
For example if the values returned by "select @@datadir, @@audit_log_file; " are  /usr/local/mysql/data/,  audit.log
sudo cat  /usr/local/mysql/data/audit.log |egrep proxies_priv

The audit data will look similar to the example below:
{ "timestamp": "2020-08-19 21:10:39", "id": 1, "class": "general", "event": "status", "connection_id": 13, "account": { "user": "auditme", "host": "localhost" }, "login": { "user": "auditme", "os": "", "ip": "::1", "proxy": "" }, "general_data": { "command": "Query", "sql_command": "select", "query": "select * from mysql.proxies_priv", "status": 1142 } },
Note status is 1142, like the error.

If the audit event is not present, this is a finding.)
  desc 'fix', 'If currently required, configure the MySQL Database Server to produce audit records when unsuccessful attempts to retrieve privileges/permissions occur.

See the supplemental file "MySQL80Audit.sql".'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38325r623438_chk'
  tag severity: 'medium'
  tag gid: 'V-235106'
  tag rid: 'SV-235106r623440_rule'
  tag stig_id: 'MYS8-00-001900'
  tag gtitle: 'SRG-APP-000091-DB-000325'
  tag fix_id: 'F-38288r623439_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
