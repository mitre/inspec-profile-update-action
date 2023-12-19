control 'SV-218798' do
  title 'The IIS 10.0 web server must have Multipurpose Internet Mail Extensions (MIME) that invoke OS shell programs disabled.'
  desc "Controlling what a user of a hosted application can access is part of the security posture of the web server. Any time a user can access more functionality than is needed for the operation of the hosted application poses a security issue. A user with too much access can view information that is not needed for the user's job role, or the user could use the function in an unintentional manner.

A MIME tells the web server the type of program, various file types, and extensions and what external utilities or programs are needed to execute the file type.

A shell is a program that serves as the basic interface between the user and the operating system to ensure hosted application users do not have access to these programs. Shell programs may execute shell escapes and can perform unauthorized activities that could damage the security posture of the web server."
  desc 'check', 'Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Under IIS, double-click the "MIME Types" icon.

From the "Group by:" drop-down list, select "Content Type".

From the list of extensions under "Application", verify MIME types for OS shell program extensions have been removed, to include at a minimum, the following extensions:

.exe
.dll
.com
.bat
.csh

If any OS shell MIME types are configured, this is a finding.'
  desc 'fix', 'Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Under IIS, double-click the "MIME Types" icon.

From the "Group by:" drop-down list, select "Content Type".

From the list of extensions under "Application", remove MIME types for OS shell program extensions, to include at a minimum, the following extensions:

.exe
.dll
.com
.bat
.csh

Under the "Actions" pane, click "Apply".'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20270r310869_chk'
  tag severity: 'medium'
  tag gid: 'V-218798'
  tag rid: 'SV-218798r879587_rule'
  tag stig_id: 'IIST-SV-000124'
  tag gtitle: 'SRG-APP-000141-WSR-000081'
  tag fix_id: 'F-20268r310870_fix'
  tag 'documentable'
  tag legacy: ['SV-109235', 'V-100131']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
