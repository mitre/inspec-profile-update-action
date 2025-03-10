control 'SV-235116' do
  title 'The MySQL Database Server 8.0 must generate audit records when unsuccessful attempts to modify security objects occur.'
  desc 'Changes in the database objects (tables, views, procedures, functions) that record and control permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized changes to the security subsystem could go undetected. The database could be severely compromised or rendered inoperative.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', %q(Review the system documentation to determine if MySQL Server is required to audit when unsuccessful attempts to modify security objects occur.

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

To check if the audit filters in place are generating records when unsuccessful attempts to modify security objects occur, run the following as a user without administrator-level privileges:
update mysql.global_grants set host='%' where PRIV='XXXX’;

Review the audit log by running the Linux command:
sudo cat  <directory where audit log files are located>/audit.log|egrep global_grants
For example if the values returned by - "select @@datadir, @@audit_log_file; " are  /usr/local/mysql/data/,  audit.log
sudo cat  /usr/local/mysql/data/audit.log |egrep global_grants

The audit data will look similar to the example below and contain a non-zero status value:
{ "timestamp": "2020-08-19 21:32:27", "id": 2, "class": "general", "event": "status", "connection_id": 9, "account": { "user": "root", "host": "localhost" }, "login": { "user": "root", "os": "", "ip": "::1", "proxy": "" }, "general_data": { "command": "Query", "sql_command": "update", "query": "update mysql.global_grants set host='%' where PRIV='XXXX'", "status": 1421 } }

If the audit event is not present, this is a finding.)
  desc 'fix', 'If currently required, configure the MySQL Database Server to produce audit records when unsuccessful attempts to modify security objects occur.

See the supplemental file "MySQL80Audit.sql".'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38335r623468_chk'
  tag severity: 'medium'
  tag gid: 'V-235116'
  tag rid: 'SV-235116r638812_rule'
  tag stig_id: 'MYS8-00-002900'
  tag gtitle: 'SRG-APP-000496-DB-000335'
  tag fix_id: 'F-38298r623469_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
