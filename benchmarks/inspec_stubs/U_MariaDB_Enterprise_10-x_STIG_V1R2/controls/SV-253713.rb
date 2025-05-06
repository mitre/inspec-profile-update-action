control 'SV-253713' do
  title 'Access to database files must be limited to relevant processes and to authorized, administrative users.'
  desc 'Applications, including MariaDB, must prevent unauthorized and unintended information transfer via shared system resources. Permitting only MariaDB processes and authorized, administrative users to have access to the files where the database resides helps ensure that those files are not shared inappropriately and are not open to backdoor access and manipulation.'
  desc 'check', %q(By default, all of the MariaDB database files, log files, and backup files are located in the /var/lib/mysql.

To find the location of the datadir run this command:

Mariadb > SHOW GLOBAL VARIABLES LIKE 'datadir';
 
Check the /etc/my.cnf file for the following variables to determine if any of these files have a nondefault location configured. Only variables that specify a directory different from datadir will be in a different directory. If the variable only specifies a file name, that file will still be in the default directory.

error_log
innodb_log_group_home_dir
innodb_temp_data_file_path
innodb_tmpdir
innodb_undo_directory
innodb_temp_data_file_path
innodb_tmpdir
log_bin_basename
log_error
relay_log_basename
relay_log_file_info
sql_error_log_filename
tmpdir

Review the permissions granted to users by the operating system/file system on the database files, database log files, and database backup files. 

To verify that all files are owned by the database administrator and have the correct permissions, run the following as the database administrator: 

$ sudo su - root
$ ls -lR {datadir}
$ ls -lR  other directories defined by variables above

If using mysqldump or another tool for backups, also run the "ls" command as above on the directory that will be containing the backup file.
    
If any files are not owned by the database administrator or allow anyone but the database administrator to read/write/execute, this is a finding. 

If any user/role who is not an authorized system administrator with a need-to-know, database administrator with a need-to-know, or system account for running MariaDB processes is permitted to read/view any of these files, this is a finding.)
  desc 'fix', "By default all of the MariaDB database files, log files, and backup files are located in the /var/lib/mysql.

To find the location of the datadir run this command:

Mariadb > SHOW GLOBAL VARIABLES LIKE 'datadir';

Check the /etc/my.cnf file for the following variables to determine if any of these files have a nondefault location configured. Only variables that specify a directory different from datadir will be in a different directory. If the variable only specifies a file name that file will still be in the datadir directory.

error_log
innodb_log_group_home_dir
innodb_temp_data_file_path
innodb_tmpdir
innodb_undo_directory
innodb_temp_data_file_path
innodb_tmpdir
log_bin_basename
log_error
relay_log_basename
relay_log_file_info
sql_error_log_filename
tmpdir

Configure the permissions granted by the operating system/file system on the database files, database log files, and database backup files so that only relevant system accounts and authorized system administrators and database administrators with a need to know are permitted to read/view these files.

Any files (e.g., extra configuration files) created in datadir, or a nondefault directory defined by a variable above, must be owned by the database administrator, with only owner permissions to read, write, and execute."
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57165r841662_chk'
  tag severity: 'medium'
  tag gid: 'V-253713'
  tag rid: 'SV-253713r841664_rule'
  tag stig_id: 'MADB-10-005600'
  tag gtitle: 'SRG-APP-000243-DB-000374'
  tag fix_id: 'F-57116r841663_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
