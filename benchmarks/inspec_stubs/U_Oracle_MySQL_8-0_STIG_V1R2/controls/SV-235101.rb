control 'SV-235101' do
  title 'The audit information produced by the MySQL Database Server 8.0 must be protected from unauthorized deletion.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods, which will depend upon system architecture and design.  

Some commonly employed methods include ensuring log files enjoy the proper file system permissions utilizing file system protections; restricting access; and backing up log data to ensure log data is retained.  

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. 

Deletion of database audit data could mask the theft of, or the unauthorized modification of, sensitive data stored in the database.'
  desc 'check', %q(Review locations of audit logs, both internal to the database and database audit logs located at the operating system level.

Verify there are appropriate controls and permissions to protect the audit information from unauthorized access.

Run this script in the database to find the path and file name:
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME LIKE 'audit_log_file';

If there is no path for audit_log_file then the audit files are located in the datadir. Run the this script to find the data directory:
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME LIKE 'datadir';

From the OS command line, run: 
ls -l <directory where audit log files are located>
ls -l <directory where audit log files are located> | grep -i <audit_file_name>
For example if the values returned by - "select @@datadir, @@audit_log_file; " are  /usr/local/mysql/data/,  audit.log
ls -l  /usr/local/mysql/data/

See below for an example:
Note: .enc file extension means the files are encrypted.

ls -l  <directory where audit log files are located>/ | grep -i audit
-rw-r-----    1 _mysql  _mysql  10083871 Apr 16 15:38 audit.20190416T203832.log
-rw-r-----    1 _mysql  _mysql    398709 Apr 18 10:34 audit.20190418T153446.log
-rw-r-----    1 _mysql  _mysql     15237 Apr 18 10:44 audit.20190418T154402.log
-rw-r-----    1 _mysql  _mysql    876206 Apr 24 14:00 audit.20190424T190008.log
-rw-r-----    1 _mysql  _mysql     30208 Apr 24 14:10 audit.20190424T191044.log.enc

If the owner and group are not "mysql" or "_mysql", this is a finding.

If the directory or file permissions are more permissive than owner having Read/Write (RW) and group having Read (R) access to the audit files, aka "750", this is a finding.)
  desc 'fix', 'Apply controls and modify permissions to protect database audit log data from unauthorized access, whether stored in the database itself or at the OS level.

sudo vi /etc/my.cnf
[mysqld]
audit-log=FORCE_PLUS_PERMANENT
audit-log-format=JSON
audit-log-encryption=AES

After changing the my.cnf, restart the server.

If not performed already, set the audit log password.
SELECT audit_log_encryption_password_set(password);

Set appropriate permissions on the directory and audit files.
sudo chown mysql <audit directory path>
sudo chgrp mysql <audit directory path>
Change permissions 
chmod 750 <directory path>'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38320r623423_chk'
  tag severity: 'medium'
  tag gid: 'V-235101'
  tag rid: 'SV-235101r623425_rule'
  tag stig_id: 'MYS8-00-001400'
  tag gtitle: 'SRG-APP-000120-DB-000061'
  tag fix_id: 'F-38283r623424_fix'
  tag 'documentable'
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
