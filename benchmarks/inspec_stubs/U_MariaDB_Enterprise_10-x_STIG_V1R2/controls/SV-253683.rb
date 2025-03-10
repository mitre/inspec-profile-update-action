control 'SV-253683' do
  title 'MariaDB must protect its audit configuration from unauthorized modification.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys to make access decisions regarding the modification of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
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
  tag check_id: 'C-57135r841572_chk'
  tag severity: 'medium'
  tag gid: 'V-253683'
  tag rid: 'SV-253683r841574_rule'
  tag stig_id: 'MADB-10-002400'
  tag gtitle: 'SRG-APP-000122-DB-000203'
  tag fix_id: 'F-57086r841573_fix'
  tag 'documentable'
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
