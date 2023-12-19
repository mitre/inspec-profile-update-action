control 'SV-235153' do
  title 'Access to database files must be limited to relevant processes and to authorized, administrative users.'
  desc 'Applications, including DBMSs, must prevent unauthorized and unintended information transfer via shared system resources. Permitting only DBMS processes and authorized, administrative users to have access to the files where the database resides helps ensure that those files are not shared inappropriately and are not open to backdoor access and manipulation.

As a general rule, distributed files and resources should follow the principal of least privilege, which requires that users, processes, programs, and other system components only have access to information and resources required for their legitimate purpose.'
  desc 'check', "Review the permissions granted to users via the operating system/file system on the instance files, database files, database redo, undo, archive, bin and audit log files, and database backup files.

If any user/role who is not an authorized system administrator with a need to know or database administrator with a need to know, or a system account for running DBMS processes permitted to read/view any of these files, this is a finding.

Note: When the instance and database directories are created by mysql installations packages, the permissions are secure and should not be changed.

Run ls -l on the various files and directory. Permissions should be limited to the mysql user and mysql group.

Use the following queries/commands to find the locations of instance directory, database directory, transaction logs directory, archive logs directory, audit logs directory, and backup files location.

SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME LIKE '%dir' or VARIABLE_NAME LIKE '%file' order by  VARIABLE_NAME;

Regarding Linux default installation:
Proper permissions are shown below. If the permissions are more permissive for a Location Type, this is a finding.

The following table shows directory and file permissions for the generic binary distribution installation of MySQL Enterprise Edition for Linux x86-64 on Oracle Linux that is described in this guide.

As indicated previously, most of the MySQL installation can be owned by root. The exceptions are the data directory, the error log file, the mysql-files directory, the pid file, and the socket file, to which the mysql user must have write access. Files and resources to which the mysql user requires read access include configuration files (/etc/my.cnf) and the MySQL binaries (for example /usr/local/mysql/bin).

Desc/Typical Location                   Owner                Directory       File
                                                                                        Permissions     Permissions
---------------------                                -----                     -----------           -----------
Client and utility programs directory
/usr/local/mysql/bin                      root                    drwxr-xr-x
mysqld server   
/usr/local/mysql/bin                      root                   drwxr-xr-x      -rwxr-xr-x
MySQL configuration file        
/etc/my.cnf                                      root                  drwxr-xr-x      -rw-r--r--
Data directory  
/usr/local/mysql/data                   mysql                drwxr-x---
Error log file  
 <directory where audit log files are located>/host_name.err     
                                                           mysql                drwxr-x---      -rw-------
secure_file_priv directory      
/usr/local/mysql/mysql-files        mysql                drwxr-x---
mysqld systemd service file     
/usr/lib/systemd/system/mysqld.service  
                                                           root                   drwxr-xr-x     -rw-r--r--
systemd tmpfiles configuration file     
/usr/lib/tmpfiles.d/mysql.conf   root                   drwxr-xr-x      -rw-r--r--
pid file        
 <directory where audit log files are located>/mysqld.pid        
                                                          mysql                 drwxr-x---      -rw-r-----
socket file     
/tmp/mysql.sock                           mysql                 drwxrwxrwt srwxrwxrwx
Unix manual pages directory     
/usr/local/mysql/man                  root                   drwxr-xr-x
Include Header files directory  
/usr/local/mysql/include             root                   drwxr-xr-x
Libraries directory     
/usr/local/mysql/lib                      root                   drwxr-xr-x
Miscellaneous support files directory   
/usr/local/mysql/support-files   root                   drwxr-xr-x
Miscellaneous files directory   
/usr/local/mysql/share                root                   drwxr-xr-x"
  desc 'fix', 'Configure the permissions granted by the operating system/file system on the database files, database log files, and database backup files so that only relevant system accounts and authorized system administrators and database administrators with a need to know are permitted to read/view these files. Remove any unauthorized permission grants from MySQL data, audit, certificate, key, or other directories.'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38372r623579_chk'
  tag severity: 'medium'
  tag gid: 'V-235153'
  tag rid: 'SV-235153r879649_rule'
  tag stig_id: 'MYS8-00-006800'
  tag gtitle: 'SRG-APP-000243-DB-000374'
  tag fix_id: 'F-38335r623580_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
