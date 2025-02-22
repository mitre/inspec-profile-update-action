control 'SV-253776' do
  title 'MariaDB must off-load audit data to a separate log management facility; this must be continuous and in near real time for systems with a network connection to the storage facility and weekly or more often for stand-alone systems.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity. 

MariaDB writes audit records to files in the file system, to other kinds of local repository, or directly to a centralized log management system. Whatever the method used, it must be compatible with off-loading the records to the centralized system.'
  desc 'check', "Check if the variable server_audit_output_type is set to syslog, and verify the operating system is using a centralized syslog utility such as rsyslogd. 

MariaDB> SHOW GLOBAL VARIABLES LIKE 'server_audit_output_type'; 

If not, this is a finding."
  desc 'fix', "To set up the audit logs to write to sylog:

Edit the mariadb-enterprise.cnf file. Add the following under the [mariadb] section:  

server_audit_output_type = 'syslog' 

After the .cnf file is updated and saved, the mariadb database service must be restarted."
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57228r841851_chk'
  tag severity: 'medium'
  tag gid: 'V-253776'
  tag rid: 'SV-253776r841853_rule'
  tag stig_id: 'MADB-10-012400'
  tag gtitle: 'SRG-APP-000515-DB-000318'
  tag fix_id: 'F-57179r841852_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
