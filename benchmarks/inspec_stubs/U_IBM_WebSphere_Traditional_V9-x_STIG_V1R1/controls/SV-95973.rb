control 'SV-95973' do
  title 'The WebSphere Application Server wsadmin file must be protected from unauthorized access.'
  desc 'Protecting log data also includes identifying and protecting the tools used to view and manipulate log data. 

Depending upon the log format and application, system and application log tools may provide the only means to manipulate and manage application and system log data. 

It is, therefore, imperative that access to log tools be controlled and protected from unauthorized access. 

Application servers provide a web- and/or a command line-based management functionality for managing the application server log capabilities. In addition, subsets of log tool components may be stored on the file system as jar or xml configuration files. The application server must ensure that in addition to protecting any web-based log tools, any file system-based tools are protected as well.'
  desc 'check', 'Review System Security Plan and the system documentation.

Identify the home folder and user account for the WebSphere installation.

Log on to the operating system that is hosting the WebSphere application server. By default, WebSphere will be installed in the "/opt/IBM/Websphere" folder on UNIX like systems and in the "C:\\Program Files\\IBM\\Websphere\\" folder on Windows systems.

On UNIX systems, verify file permissions for the "WebSphere" folder are set to "770" for the WebSphere user, group, and other. Permissions do not propagate to sub-folders.

On Windows systems, verify file permissions for "WebSphere" folder allow SYSTEM, WebSphere User, and Admin Group full control. Permissions do not propagate to sub-folders.

If file permissions exceed these restrictions, this is a finding.'
  desc 'fix', 'On the system hosting the WebSphere application server, log on to the operating system with admin rights.

Navigate to the "WebSphere" folder, and change permissions on the folder. Do not propagate permissions to sub-folders.

For UNIX systems: set the "WebSphere" folder permissions to "770".

For Windows systems: set the "WebSphere" folder permission to allow full control for SYSTEM, WebSphere user, and Admin Group. Do not propagate permissions to sub-folders.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80957r2_chk'
  tag severity: 'medium'
  tag gid: 'V-81259'
  tag rid: 'SV-95973r1_rule'
  tag stig_id: 'WBSP-AS-000770'
  tag gtitle: 'SRG-APP-000121-AS-000081'
  tag fix_id: 'F-88039r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
