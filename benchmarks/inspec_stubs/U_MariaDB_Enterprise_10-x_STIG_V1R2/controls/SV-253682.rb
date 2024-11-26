control 'SV-253682' do
  title 'MariaDB must protect its audit features from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. 

Depending upon the log format and application, system and application log tools may provide the only means to manipulate and manage application and system log data. It is, therefore, imperative that access to audit tools be controlled and protected from unauthorized access. 

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, OS-provided audit tools, vendor-provided audit tools, and open source audit tools needed to successfully view and manipulate audit information system activity and records. 

If an attacker were to gain access to audit tools, he could analyze audit logs for system weaknesses or weaknesses in the auditing itself. An attacker could also manipulate logs to hide evidence of malicious activity.'
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
  tag check_id: 'C-57134r841569_chk'
  tag severity: 'medium'
  tag gid: 'V-253682'
  tag rid: 'SV-253682r841571_rule'
  tag stig_id: 'MADB-10-002300'
  tag gtitle: 'SRG-APP-000121-DB-000202'
  tag fix_id: 'F-57085r841570_fix'
  tag 'documentable'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
