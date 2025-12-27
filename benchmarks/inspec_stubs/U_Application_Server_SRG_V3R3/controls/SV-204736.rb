control 'SV-204736' do
  title 'The application server must protect log tools from unauthorized modification.'
  desc 'Protecting log data also includes identifying and protecting the tools used to view and manipulate log data. 

Depending upon the log format and application, system and application log tools may provide the only means to manipulate and manage application and system log data. 

It is, therefore, imperative that access to log tools be controlled and protected from unauthorized modification. If an attacker were to modify log tools, he could also manipulate logs to hide evidence of malicious activity. 

Application servers provide a web- and/or a command line-based management functionality for managing the application server log capabilities. In addition, subsets of log tool components may be stored on the file system as jar or xml configuration files. The application server must ensure that in addition to protecting any web-based log tools, any file system-based tools are protected as well.'
  desc 'check', 'Review the application server documentation and server configuration to determine if the application server protects log tools from unauthorized modification. Request a system administrator attempt to modify log tools while logged into the server in a role that does not have the requisite privileges.

Locate binary copies of log tool executables that are located on the file system and attempt to modify using unprivileged credentials.

If the application server does not protect log tools from unauthorized modification, this is a finding.'
  desc 'fix', 'Configure the application server or the OS to protect log tools from unauthorized modification.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4856r282855_chk'
  tag severity: 'medium'
  tag gid: 'V-204736'
  tag rid: 'SV-204736r508029_rule'
  tag stig_id: 'SRG-APP-000122-AS-000082'
  tag gtitle: 'SRG-APP-000122'
  tag fix_id: 'F-4856r282856_fix'
  tag 'documentable'
  tag legacy: ['SV-46501', 'V-35214']
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
