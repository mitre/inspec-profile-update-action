control 'SV-235155' do
  title 'The MySQL Database Server 8.0 must protect the confidentiality and integrity of all information at rest.'
  desc 'This control is intended to address the confidentiality and integrity of information at rest in non-mobile devices and covers user information and system information. Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive, tape drive) within an organizational information system. Applications and application users generate information throughout the course of their application use. 

User data generated, as well as application-specific configuration data, needs to be protected. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate. 

If the confidentiality and integrity of application data is not protected, the data will be open to compromise and unauthorized modification.'
  desc 'check', %q(Apply appropriate controls to protect the confidentiality and integrity of data at rest in the database.

Using SQL determine if all data-at-rest is encrypted.

SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables where variable_name = 'audit_log_encryption';

If "audit_log_encryption" is not set to "AES", this is a finding.

SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables where variable_name = 'binlog_encryption';

If "binlog_encrypt" is not set to "ON", this is a finding.

SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables where variable_name = 'innodb_redo_log_encrypt';

If "innodb_redo_log_encrypt" is not set to "ON", this is a finding.

SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables where variable_name = 'innodb_undo_log_encrypt';

If "innodb_undo_log_encrypt" is not set to "ON", this is a finding.

SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME like 'general_log';

If "general_log"is not "OFF", this is a finding.

Find encryption status for all mysql table and tablespaces.
SELECT
    `INNODB_TABLESPACES`.`NAME`,
    `INNODB_TABLESPACES`.`ENCRYPTION`
FROM `information_schema`.`INNODB_TABLESPACES`;

If any tablespace is not ENCRYPTION set to "Y (yes)", this is a finding.

SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables where variable_name = 'table_encryption_privilege_check';

If "innodb_redo_log_encrypt" is not set to "ON", this is a finding.)
  desc 'fix', "Apply appropriate MySQL Database 8.0 controls to protect the confidentiality and integrity of data at rest in the database.

sudo vi /etc/my.cnf
[mysqld]
audit-log=FORCE_PLUS_PERMANENT
audit-log-format=JSON
audit-log-encryption=AES

Turn on binlog encryption
set persist binlog_encryption=ON;

Turn on undo and redo log encryption
set persist innodb_redo_log_encrypt=ON;
set persist innodb_undo_log_encrypt=ON;

Enable encryption for a new file-per-table tablespace, specify the ENCRYPTION option in a CREATE TABLE statement. 
The following example assumes that innodb_file_per_table is enabled.
mysql> CREATE TABLE t1 (c1 INT) ENCRYPTION='Y';

To enable encryption for an existing file-per-table tablespace, specify the ENCRYPTION option in an ALTER TABLE statement.
mysql> ALTER TABLE t1 ENCRYPTION='Y';

To disable encryption for file-per-table tablespace, set ENCRYPTION='N' using ALTER TABLE.
mysql> ALTER TABLE t1 ENCRYPTION='N';

Disable the general_log
SET PERSIST general_log = 'OFF';"
  impact 0.7
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38374r623585_chk'
  tag severity: 'high'
  tag gid: 'V-235155'
  tag rid: 'SV-235155r638812_rule'
  tag stig_id: 'MYS8-00-007200'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-38337r623586_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
