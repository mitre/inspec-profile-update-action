control 'SV-235097' do
  title 'MySQL Database Server 8.0  must produce audit records containing sufficient information to establish what type of events occurred.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit record content that may be necessary to satisfy the requirement of this policy includes, for example, time stamps, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application. 

Database software is capable of a range of actions on data stored within the database. It is important, for accurate forensic analysis, to know exactly what actions were performed. This requires specific information regarding the event type to which an audit record refers. If event type information is not recorded and stored with the audit record, the record itself is of very limited use.

MySQL provides auditing using the MySQL Enterprise Audit Log Plugin. When installed, the audit plugin enables MySQL Server to produce a log file containing an audit record of server activity. The log contents include when clients connect and disconnect, and what actions they perform while connected, such as which databases and tables they access.'
  desc 'check', %q(Verify, using vendor and system documentation if necessary, that the Database Management System (DBMS) is configured to use MySQL auditing features, or that a third-party product or custom code is deployed and configured to satisfy this requirement.

Check MySQL auditing to determine whether organization-defined auditable events are being audited by the system.

SELECT PLUGIN_NAME, plugin_status FROM INFORMATION_SCHEMA.PLUGINS
      WHERE PLUGIN_NAME LIKE 'audit_log' ;

If the results are not 'audit_log' and plugin_status='ACTIVE' , this is a finding.

Next, determine if the audit log is encrypted: 
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME LIKE 'audit_log_encryption' ;

If nothing is returned or the value for audit_log_encryption is not AES, this is a finding.

Review the audit files in the file systems.

Run the following command using the audit log location from above and review its output:
ls -l  <directory where audit log files are located>/audit*log*

For example, if the values returned by - "select @@datadir, @@audit_log_file; " are  /usr/local/mysql/data/,  audit.log
ls -l  /usr/local/mysql/data/audit.log
Example output:
-rw-r-----    1 _mysql  _mysql   3935888 Apr 25 12:34 audit.20190425T173437.log.enc
-rw-r-----    1 _mysql  _mysql      2336 Apr 25 12:35 audit.20190425T173527.log.enc
-rw-r-----    1 _mysql  _mysql  13763984 Apr 30 14:04 audit.log.enc

Next, verify the log files have set permissions the log_destination:
If the user owner is not "mysql", this is a finding.
If the group owner is not "mysql", this is a finding.
If the file is more permissive than "640", this is a finding.
Check that the files end with the ".enc" file extension.  If they do not, this means they are in plaintext, and this is a finding.

Run following command to verify the directory permissions and review its output:
ls -l /usr/local/mysql/data

Example output:
drwxr-x---   _mysql  _mysql    1760 Apr 26 09:55 data

Next, verify the log files have set permissions for the log_destination:
If the user owner is not "mysql", this is a finding.
If the group owner is not "mysql", this is a finding.
If more permissive than "750", this is a finding.

If there are no audit log files, then organizational auditable events are not being audited, and this is a finding.

To confirm that MySQL audit is capturing sufficient information to establish the identity of the user/subject or process, perform a successful auditable action and an auditable action that results in an SQL error, and then view the results in the audit file, whichever is in use.

If no audit event is returned for the auditable actions just performed, this is a finding.)
  desc 'fix', %q(Configure DBMS auditing to audit standard and organization-defined auditable events, with the audit record to include what type of event occurred. 

Use this process to ensure auditable events are captured:

Configure MySQL database server 8.0 for auditing and configure audit settings to include required events as part of the audit record.

To install MySQL Enterprise Audit:
Run the audit_log_filter_linux_install.sql script located in the sharedirectory of your MySQL installation. This can be determined by running – select @@basedir;
For example if the basedir is /usr/local/mysql 
shell> bin/mysql -u root -p < /usr/local/mysql/share/audit_log_filter_linux_install.sql

Verify the plugin installation by running:
SELECT PLUGIN_NAME, PLUGIN_STATUS
       FROM INFORMATION_SCHEMA.PLUGINS
       WHERE PLUGIN_NAME LIKE 'audit%';
The value for audit_log should return ACTIVE.

To prevent the plugin from being removed at runtime, add the --audit-log option under the [mysqld] option group in the MySQL configuration file (/etc/my.cnf) with a setting of FORCE_PLUS_PERMANENT.

audit-log=FORCE_PLUS_PERMANENT

Restart the server to apply the configuration change.

By default, rule-based audit log filtering logs no auditable events for any users. To produce log-everything behavior with rule-based filtering, create a filter to enable logging of all events and assign it to the audit all accounts.

Run the following statements to filter all activity for all users:
SELECT audit_log_filter_set_filter('log_all', '{ "filter": { "log": true } }');
SELECT audit_log_filter_set_user('%', 'log_all');
SELECT audit_log_filter_set_user('%', 'log_all');)
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38316r623411_chk'
  tag severity: 'medium'
  tag gid: 'V-235097'
  tag rid: 'SV-235097r879563_rule'
  tag stig_id: 'MYS8-00-000300'
  tag gtitle: 'SRG-APP-000095-DB-000039'
  tag fix_id: 'F-38279r623412_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
