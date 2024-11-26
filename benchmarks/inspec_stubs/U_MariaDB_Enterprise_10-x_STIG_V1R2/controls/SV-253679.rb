control 'SV-253679' do
  title 'The audit information produced by MariaDB must be protected from unauthorized read access.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, copy, etc.

This requirement can be achieved through multiple methods which will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions utilizing file system protections and limiting log data location. 

Additionally, applications with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring that audit information is protected from unauthorized access.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.'
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
  tag check_id: 'C-57131r841560_chk'
  tag severity: 'medium'
  tag gid: 'V-253679'
  tag rid: 'SV-253679r841562_rule'
  tag stig_id: 'MADB-10-002000'
  tag gtitle: 'SRG-APP-000118-DB-000059'
  tag fix_id: 'F-57082r841561_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
