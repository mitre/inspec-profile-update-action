control 'SV-235099' do
  title 'The audit information produced by the MySQL Database Server 8.0 must be protected from unauthorized read access.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to their advantage.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, copy, etc.

This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions utilizing file system protections and limiting log data location. 

Additionally, applications with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring that audit information is protected from unauthorized access.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

If the value of audit_log_file is a relative path name, the plugin interprets it relative to the data directory. If the value is a full path name, the plugin uses the value as is. A full path name may be useful if it is desirable to locate audit files on a separate file system or directory. For security reasons, write the audit log file to a directory accessible only to the MySQL server and to users with a legitimate reason to view the log.'
  desc 'check', %q(Review locations of audit logs, both internal to the database and database audit logs located at the operating system level.

Verify there are appropriate controls and permissions to protect the audit information from unauthorized access.

Run this script in the database to find the path and file name:
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME LIKE 'audit_log_file';

If there is no path for audit_log_file, then the audit files are located in the datadir. Run the this script to find the data directory:
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
  tag check_id: 'C-38318r623417_chk'
  tag severity: 'medium'
  tag gid: 'V-235099'
  tag rid: 'SV-235099r623419_rule'
  tag stig_id: 'MYS8-00-001200'
  tag gtitle: 'SRG-APP-000118-DB-000059'
  tag fix_id: 'F-38281r623418_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
