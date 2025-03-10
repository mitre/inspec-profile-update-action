control 'SV-250329' do
  title 'The WebSphere Liberty Server must protect log tools from unauthorized access.'
  desc 'Protecting log data also includes identifying and protecting the tools used to view and manipulate log data. Depending on the log format and application, system and application log tools may provide the only means to manipulate and manage application and system log data. Therefore, it is imperative that access to log tools be controlled and protected from unauthorized access. 

Application servers provide a web- and/or a command line-based management functionality for managing the application server log capabilities. In addition, subsets of log tool components may be stored on the file system as jar or xml configuration files. The application server must ensure that in addition to protecting any web-based log tools, any file system-based tools are protected as well.'
  desc 'check', 'As a user with local file access to the /opt/IBM/WebSphere/Liberty/bin folder, verify the following audit tool files have the correct file permissions of 755.

binaryLog
auditUtility

If the file permissions for these files are not set to 755, this is a finding.'
  desc 'fix', 'As a user with local file access to the /opt/IBM/WebSphere/Liberty/bin/ folder, use the chmod command to configure the correct file permissions of 755 for the following files.

binaryLog
auditUtility'
  impact 0.5
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53764r795038_chk'
  tag severity: 'medium'
  tag gid: 'V-250329'
  tag rid: 'SV-250329r795040_rule'
  tag stig_id: 'IBMW-LS-000280'
  tag gtitle: 'SRG-APP-000121-AS-000081'
  tag fix_id: 'F-53718r795039_fix'
  tag 'documentable'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
