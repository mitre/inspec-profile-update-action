control 'SV-253680' do
  title 'The audit information produced by MariaDB must be protected from unauthorized modification.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data the information system and/or the application must protect audit information from unauthorized modification. 

This requirement can be achieved through multiple methods that will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions and limiting log data locations. 

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights that the user enjoys to make access decisions regarding the modification of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. 

Modification of database audit data could mask the theft of, or the unauthorized modification of, sensitive data stored in the database.'
  desc 'check', "Determine if the MariaDB Enterprise Audit plugin is logging to a file or syslog. 

MariaDB> SHOW GLOBAL VARIABLES LIKE 'server_audit_output_type';
 
If FILE, find the location of the audit log:
 
MariaDB> SHOW GLOBAL VARIABLES LIKE 'server_audit_file_path';

If FILE, check the permission of the file: 

$ sudo ls -al /path/to/audit.log
 
Consult the organization's security guide on acceptable permissions and ownership of logs with respect to who can modify them. Verify the log files have the set configurations. 
 
If the permissions are not set to the organization's standards, this is a finding.
  
If the MariaDB server is configured to use syslog for logging, consult the organization's syslog setting for permissions and ownership of logs with respect to who can modify them."
  desc 'fix', "If the audit.log file permissions do not comply with organization's standards, change the permissions. Example: 

$ chown user:group /path/to/audit.log
$ chmod 660 /path/to/audit.log

If the MariaDB server is configured to use syslog for logging, consult the organization's syslog setting for permissions and ownership of logs with respect to who can modify them."
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57132r841563_chk'
  tag severity: 'medium'
  tag gid: 'V-253680'
  tag rid: 'SV-253680r841565_rule'
  tag stig_id: 'MADB-10-002100'
  tag gtitle: 'SRG-APP-000119-DB-000060'
  tag fix_id: 'F-57083r841564_fix'
  tag 'documentable'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
