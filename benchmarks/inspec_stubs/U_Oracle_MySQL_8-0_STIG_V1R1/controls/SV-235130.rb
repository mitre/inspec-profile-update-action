control 'SV-235130' do
  title 'The MySQL Database Server 8.0 must generate audit records when concurrent logons/connections by the same user from different workstations.'
  desc 'For completeness of forensic analysis, it is necessary to track who logs on to the Database Management System (DBMS).

Concurrent connections by the same user from multiple workstations may be valid use of the system; or such connections may be due to improper circumvention of the requirement to use the CAC for authentication; or they may indicate unauthorized account sharing; or they may be because an account has been compromised.

(If the fact of multiple, concurrent logons by a given user can be reliably reconstructed from the log entries for other events (logons/connections; voluntary and involuntary disconnections), then it is not mandatory to create additional log entries specifically for this).'
  desc 'check', %q(Review the system documentation to determine if MySQL Server is required to audit the concurrent logons/connections by the same user from different workstations.

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

To check if the audit filters that are in place are generating records when multiple connections occur:

Run multiple connections from the same user without logging out and from different IP addresses.

Review the audit log:
sudo cat  <directory where audit log files are located>/audit.log | egrep <username>
For example if the values returned by - "select @@datadir, @@audit_log_file; " are  /usr/local/mysql/data/,  audit.log and the user is fewconnects then
sudo cat  /usr/local/mysql/data/audit.log |egrep fewconnects

 { "connection_type": "ssl", "status": 0, "db": "", "connection_attributes": { "_pid": "9132", "_os": "macos10.14", "_platform": "x86_64", "_client_version": "8.0.20", "_client_name": "libmysql", "program_name": "mysqlsh" } } },
{ "timestamp": "2020-08-31 18:03:41", "id": 0, "class": "connection", "event": "connect", "connection_id": 28, "account": { "user": "fewconnects", "host": "localhost" }, "login": { "user": "fewconnects", "os": "", "ip": "", "proxy": "" }, "connection_data": { "connection_type": "ssl", "status": 0, "db": "", "connection_attributes": { "_pid": "9132", "_os": "macos10.14", "_platform": "x86_64", "_client_version": "8.0.20", "_client_name": "libmysql", "program_name": "mysqlsh" } } }
{ "timestamp": "2020-08-31 18:11:05", "id": 12, "class": "connection", "event": "connect", "connection_id": 38, "account": { "user": "fewconnects", "host": "localhost" }, "login": { "user": "fewconnects", "os": "", "ip": "93.122.141.147", "proxy": "" }, "connection_data": { "connection_type": "ssl", "status": 0, "db": "", "connection_attributes": { "_pid": "903", "_os": "macos10.15", "_platform": "x86_64", "_client_version": "8.0.20", "_client_name": "libmysql", "program_name": "MySQLWorkbench" } } },
Note that each connection has a different connection_id - indicating distinctly auditing multiple connections. Here there are connections from mysqlsh and MySQLWorkbench; the event type is "event": “connect” and the "user": "fewconnects", "os": "", "ip": “127.0.0.1” and "login": { "user": "fewconnects", "os": "", "ip": “93.122.141.147” - that is with different IPs from the different workstations.

If the audit events are not present, this is a finding.

If currently required, configure the MySQL Database Server to produce audit records when connections occur.

See the supplemental file "MySQL80Audit.sql".)
  desc 'fix', 'If currently required, configure the MySQL Database Server to produce audit records when connections occur.

See the supplemental file "MySQL80Audit.sql".'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38349r623510_chk'
  tag severity: 'medium'
  tag gid: 'V-235130'
  tag rid: 'SV-235130r638812_rule'
  tag stig_id: 'MYS8-00-004300'
  tag gtitle: 'SRG-APP-000506-DB-000353'
  tag fix_id: 'F-38312r623511_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
