control 'SV-253685' do
  title 'MariaDB must limit privileges to change software modules, to include stored procedures, functions and triggers, and links to software external to the DBMS.'
  desc 'If the system were to allow any user to make changes to software libraries, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.
 
Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database code can lead to unauthorized or compromised installations.'
  desc 'check', "Review documentation to determine which users are authorized to modify the MariaDB Enterprise Server binary files and shared library paths. 
 
If any unauthorized users are granted modify rights, this is a finding.

Check what users have access to install/uninstall MariaDB Enterprise Server plugins. This privilege can be listed in one of three places: Table level, database level, or global. 

Table level:

MariaDB> SELECT user, host FROM mysql.tables_priv WHERE db = 'mysql' and table_name = ' plugin';

Database level:

MariaDB> SELECT user, host FROM mysql.db WHERE db = 'mysql' and (insert_priv = 'y') or (delete_priv = 'y') or (insert_priv = 'y' and delete_priv = 'y');

Global: 

SELECT user, host FROM mysql.user WHERE (insert_priv = 'y') or (delete_priv = 'y') or (insert_priv = 'y' and delete_priv = 'y');

If any user identified by the above queries is not authorized to install/uninstall MariaDB Enterprise Server plugins, this is a finding. 

Review monitoring procedures and implementation evidence to verify monitoring of changes to database software libraries, related applications, and configuration files is done.

Verify the list of files and directories being monitored is complete.

If monitoring does not occur or is not complete, this is a finding."
  desc 'fix', 'Remove privileges from users identified as not authorized to install/uninstall MariaDB Enterprise Server plugins.  

Implement procedures to monitor for unauthorized changes to DBMS software libraries, related software application libraries, and configuration files. If a third-party automated tool is not employed, an automated job that reports file information on the directories and files of interest and compares them to the baseline report for the same will meet the requirement.'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57137r841578_chk'
  tag severity: 'medium'
  tag gid: 'V-253685'
  tag rid: 'SV-253685r841580_rule'
  tag stig_id: 'MADB-10-002600'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-57088r841579_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
