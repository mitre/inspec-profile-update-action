control 'SV-204737' do
  title 'The application server must protect log tools from unauthorized deletion.'
  desc 'Protecting log data also includes identifying and protecting the tools used to view and manipulate log data. 

Depending upon the log format and application, system and application log tools may provide the only means to manipulate and manage application and system log data. 

It is, therefore, imperative that access to log tools be controlled and protected from unauthorized modification. If an attacker were to delete log tools, the application server administrator would have no way of managing or viewing the logs. 

Application servers provide a web- and/or a command line-based management functionality for managing the application server log capabilities. In addition, subsets of log tool components may be stored on the file system as jar, class or xml configuration files. The application server must ensure that in addition to protecting any web-based log tools, any file system-based tools are protected from unauthorized deletion as well.'
  desc 'check', 'Review the application server documentation and server configuration to determine if the application server protects log tools from unauthorized deletion.

Locate binary copies of log tool executables that are located on the file system and attempt to delete using unprivileged credentials.

If the application server does not protect log tools from unauthorized deletion, this is a finding.'
  desc 'fix', 'Configure the application server or the OS to protect log tools from unauthorized deletion.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4857r282858_chk'
  tag severity: 'medium'
  tag gid: 'V-204737'
  tag rid: 'SV-204737r508029_rule'
  tag stig_id: 'SRG-APP-000123-AS-000083'
  tag gtitle: 'SRG-APP-000123'
  tag fix_id: 'F-4857r282859_fix'
  tag 'documentable'
  tag legacy: ['V-35215', 'SV-46502']
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']
end
