control 'SV-204735' do
  title 'The application server must protect log tools from unauthorized access.'
  desc 'Protecting log data also includes identifying and protecting the tools used to view and manipulate log data. 

Depending upon the log format and application, system and application log tools may provide the only means to manipulate and manage application and system log data. 

It is, therefore, imperative that access to log tools be controlled and protected from unauthorized access. 

Application servers provide a web- and/or a command line-based management functionality for managing the application server log capabilities. In addition, subsets of log tool components may be stored on the file system as jar or xml configuration files. The application server must ensure that in addition to protecting any web-based log tools, any file system-based tools are protected as well.'
  desc 'check', 'Review the application server documentation and server configuration to determine if the application server protects log tools from unauthorized access.

Request a system administrator attempt to access log tools while logged into the server in a role that does not have the requisite privileges.

If the application server does not protect log tools from unauthorized access, this is a finding.'
  desc 'fix', 'Configure the application server or OS to protect log tools from unauthorized access.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4855r282852_chk'
  tag severity: 'medium'
  tag gid: 'V-204735'
  tag rid: 'SV-204735r508029_rule'
  tag stig_id: 'SRG-APP-000121-AS-000081'
  tag gtitle: 'SRG-APP-000121'
  tag fix_id: 'F-4855r282853_fix'
  tag 'documentable'
  tag legacy: ['SV-46500', 'V-35213']
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
