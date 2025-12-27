control 'SV-235169' do
  title 'The MySQL Database Server 8.0 must enforce access restrictions associated with changes to the configuration of the MySQL Database Server 8.0 or database(s).'
  desc 'Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system. 

Accordingly, only qualified and authorized individuals should be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'Review the security configuration of the MySQL Database Server 8.0 and database(s). If it does not enforce access restrictions associated with changes to the configuration of the MySQL Database Server 8.0 or database(s), this is a finding.

MySQL configuration can be set two ways:  
1) The mysql configuration file. This file must be owned and permissions to read or write to it limited to the mysql OS user only. 
2) Via a SET command within the server itself. These commands may be limited by limiting "server administration" privileges. User privileges can be shown using the SHOW GRANTS [FOR user]. This data is written to mysqld-auto.cnf file.

See the mysql secure configuration guide for more information.

Run the following command to check the mysql the linux permissions on my.cnf: 
ls -l /etc/my.cnf

The permissions must be:
File or Resource                Location        Owner   Directory Permissions   File Permissions
MySQL configuration file        /etc/my.cnf     root    drwxr-xr-x              -rw-r--r--

If the permissions are more permissive than the above, this is a finding.

As of mysql 8.0 configuration variables can also be set and changed using persist system variable settings that save to a file named mysqld-auto.cnf
This file is in the mysql data dir. See the example below.

sudo ls -l /usr/local/mysql-commercial-8.0.16-macos10.14-x86_64/data/mysqld-auto.cnf
-rw-r-----  1 _mysql  _mysql  2721 May 13 14:00 /usr/local/mysql-commercial-8.0.16-macos10.14-x86_64/data/mysqld-auto.cnf

If the permissions of the mysqld-auto.cnf are more permissive, this is a finding.'
  desc 'fix', 'Configure the MySQL Database Server 8.0 to enforce access restrictions associated with changes to the configuration of the MySQL Database Server 8.0 or database(s).

Check and change file permissions on the MySQL Configuration file so the mysql OS user owns and file and is the only user with read-write permissions. Use the SHOW GRANTS statements to audit who has SUPER permissions and remove any users with excess privileges.

For my.cnf, change ownership and permissions to:
File or Resource                Location        Owner   Directory Permissions   File Permissions
MySQL configuration file        /etc/my.cnf     root    drwxr-xr-x              -rw-r--r--

The mysqld-auto.cnf is created and managed by the mysql instance, as such permissions should be correct. If not correct, change "owner" to "mysql" and "rw r" to "640".'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38388r623627_chk'
  tag severity: 'medium'
  tag gid: 'V-235169'
  tag rid: 'SV-235169r855567_rule'
  tag stig_id: 'MYS8-00-009200'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag fix_id: 'F-38351r623628_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
