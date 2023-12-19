control 'SV-235110' do
  title 'The MySQL Database Server 8.0 must generate audit records when unsuccessful attempts to access categories of information (e.g., classification levels/security levels) occur.'
  desc 'Changes in categories of information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.

For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems.'
  desc 'check', %q(If classification levels/security levels labeling is not required, this is not a finding.

Review the system documentation to determine if MySQL Server is required to audit records when unsuccessful attempts to access categories of information (e.g., classification levels/security levels) occur.

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

Modify MySQL selects that check for changes to categories of information. Modify selects statements to audit when information categories are access using MySQL Audit by calling the audit_api_message_emit_udf() function and including the details related to the select. 

- An Example test -

CREATE TABLE `test_trigger`.`info_cat_test` (
  `id` INT NOT NULL,
  `name` VARCHAR(20) NULL,
  `desc` VARCHAR(20) NULL,
  `sec_level` CHAR(1) NULL,
  PRIMARY KEY (`id`));

DELIMITER $$


INSERT INTO `test_trigger`.`info_cat_test` (`id`, `name`, `desc`, `sec_level`) VALUES ('1', 'fred', 'engineer', 'H');
INSERT INTO `test_trigger`.`info_cat_test` (`id`, `name`, `desc`, `sec_level`) VALUES ('2', 'jill', 'program manager', 'M');
INSERT INTO `test_trigger`.`info_cat_test` (`id`, `name`, `desc`, `sec_level`) VALUES ('3', 'joe', 'maintenance', 'L');

Create a view using the where clause similar to that shown in the select. If inappropriate access is attempted, in this case H level, the select statement will write to the Audit log using the emit function.

SELECT `info_cat_test`.`id`,
    `info_cat_test`.`name`,
    `info_cat_test`.`desc`,
    `info_cat_test`.`sec_level`
FROM `test_trigger`.`info_cat_test` where IF(`info_cat_test`.`sec_level`= 'H', 
    CAST(audit_api_message_emit_udf('sec_level_H_ATTEMPTED_selected',
                                         'audit_select_attempt',
                                         ' H level sec data was accessed',
                                         'FOR ', name
                                         ) as CHAR), 
    'Not Audited') <> 'OK’;
The above test will write an audit event related to the selection of H sec_level data.

Review the audit log by running the Linux command:
sudo cat  <directory where audit log files are located>/audit.log | egrep sec_level_H_ATTEMPTED_selected
For example if the values returned by - "select @@datadir, @@audit_log_file; " are  /usr/local/mysql/data/,  audit.log
sudo cat  /usr/local/mysql/data/audit.log |egrep sec_level_H_ATTEMPTED_selected

If the audit event similar to the example below is not present, this is a finding. 

The audit data will look similar to the example below:
Not Audited') <> 'OK'\nLIMIT 0, 1000", "sql_command": "select" } },
{ "timestamp": "2020-08-21 14:04:53", "id": 2, "class": "message", "event": "user", "connection_id": 9, "account": { "user": "root", "host": "localhost" }, "login": { "user": "root", "os": "", "ip": "::1", "proxy": "" }, "message_data": { "component": "sec_level_H_ATTEMPTED_selected", "producer": "audit_select_attempt", "message": " H level sec data was accessed", "map": { "FOR ": "fred" } } },)
  desc 'fix', 'If currently required, configure the MySQL Database Server with views that use selects that call audit_api_message_emit_udf() function to produce audit records when selection of categories of information occurs.
Add security level details in an additional column if necessary.

Add the component for adding information to the audit log.

INSTALL COMPONENT "file://component_audit_api_message_emit”;

To transparently enforce the use of MySQL view is required.

See the supplemental file "MySQL80Audit.sql".'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38329r623450_chk'
  tag severity: 'medium'
  tag gid: 'V-235110'
  tag rid: 'SV-235110r623452_rule'
  tag stig_id: 'MYS8-00-002300'
  tag gtitle: 'SRG-APP-000494-DB-000345'
  tag fix_id: 'F-38292r623451_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
