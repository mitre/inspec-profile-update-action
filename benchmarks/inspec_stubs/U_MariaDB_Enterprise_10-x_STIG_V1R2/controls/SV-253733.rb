control 'SV-253733' do
  title 'MariaDB must produce audit records of its enforcement of access restrictions associated with changes to the configuration of the DBMS or database(s).'
  desc 'Without auditing the enforcement of access restrictions against changes to configuration, it would be difficult to identify attempted attacks and an audit trail would not be available for forensic investigation for after-the-fact actions. 

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.'
  desc 'check', "To verify that system denies are logged when unprivileged users attempt to change database configuration, run the following commands using the database administrator, and a newly created user shown here as test_user: 

MariaDB> CREATE USER 'test_user'@'localhost' IDENTIFIED BY 'TEst_Password!2';
MariaDB> CREATE DATABASE myapp;
MariaDB> CREATE TABLE myapp.mytable (a int, b char(10));

As the newly created test_user, alter the table: 
$ mariadb -u test_user -p
Enter password:
MariaDB> ALTER TABLE mytable ADD COLUMN (c int);

Check the latest log to determine if the denial is logged. For example: 
$ tail -f /var/log/mysql/audit.log
 
20190909 12:14:29,osboxes,test_user9,localhost,21,0,CONNECT,,,0
20190909 12:14:29,osboxes,test_user9,localhost,21,10,QUERY,, alter table myapp.mytable add column (c int) ,1142
20190909 12:14:29,osboxes,test_user9,localhost,21,0,DISCONNECT,,,0

If the denial is not produced, this is a finding.

By default MariaDB configuration files are owned by the OS Administrator user (here root) and cannot be edited by nonprivileged users:

$ ls -la /etc | grep my.cnf
-rw-r--r--.   1 root root      301 Aug 25 12:45 my.cnf

If my.cnf is not owned by the OS administrator (chown here as root) and does not have read and write permissions for the owner, this is a finding."
  desc 'fix', %q(The MariaDB Enterprise Audit plugin can be configured to audit these changes. 

Update necessary audit filters to include query_event ALL. Example: 

MariaDB> DELETE FROM mysql.server_audit_filters WHERE filtername = 'default';

MariaDB> INSERT INTO mysql.server_audit_filters (filtername, rule)
   VALUES ('default',
      JSON_COMPACT(
         '{
            "connect_event": [
               "CONNECT",
               "DISCONNECT"
            ],
            "query_event": [
                "ALL"
            ]
         }'
      ));

If the config files are not secured properly in the file system, change the ownership and permissions with operating system operations. 

Example: 

chown root:root /etc/my.cnf.d
chmod 644 /etc/my.cnf.d)
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57185r841722_chk'
  tag severity: 'medium'
  tag gid: 'V-253733'
  tag rid: 'SV-253733r841724_rule'
  tag stig_id: 'MADB-10-008000'
  tag gtitle: 'SRG-APP-000381-DB-000361'
  tag fix_id: 'F-57136r841723_fix'
  tag 'documentable'
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
