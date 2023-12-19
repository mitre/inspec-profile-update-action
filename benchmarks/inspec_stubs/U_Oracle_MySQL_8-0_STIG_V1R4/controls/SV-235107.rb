control 'SV-235107' do
  title 'The MySQL Database Server 8.0 must be able to generate audit records when security objects are accessed.'
  desc 'Changes to the security configuration must be tracked.

This requirement applies to situations where security data is retrieved or modified via data manipulation operations, as opposed to via specialized security functionality.

In SQL environment, types of access include, but are not necessarily limited to:
SELECT
INSERT
UPDATE
DELETE
EXECUTE'
  desc 'check', %q(Review the system documentation to determine if MySQL Server is required to audit when security objects are accessed.

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

To check if the audit filters in place are generating records to audit when security objects are accessed, run the following query:
select * from mysql.proxies_priv;

Review the audit log by running the Linux command:
sudo cat  <directory where audit log files are located>/audit.log|egrep proxies_prim
For example if the values returned by - "select @@datadir, @@audit_log_file; " are  /usr/local/mysql/data/,  audit.log
sudo cat  /usr/local/mysql/data/audit.log |egrep proxies_priv

The audit data will look similar to the example below:
{ "timestamp": "2020-08-19 21:03:39", "id": 13, "class": "general", "event": "status", "connection_id": 9, "account": { "user": "root", "host": "localhost" }, "login": { "user": "root", "os": "", "ip": "::1", "proxy": "" }, "general_data": { "command": "Query", "sql_command": "select", "query": "select * from mysql.proxies_priv\nLIMIT 0, 1000", "status": 0 } },

If the audit event is not present, this is a finding.)
  desc 'fix', 'If currently required, configure the MySQL Database Server to produce audit records when security objects are accessed.

See the supplemental file "MySQL80Audit.sql".'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38326r623441_chk'
  tag severity: 'medium'
  tag gid: 'V-235107'
  tag rid: 'SV-235107r879863_rule'
  tag stig_id: 'MYS8-00-002000'
  tag gtitle: 'SRG-APP-000492-DB-000332'
  tag fix_id: 'F-38289r623442_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
