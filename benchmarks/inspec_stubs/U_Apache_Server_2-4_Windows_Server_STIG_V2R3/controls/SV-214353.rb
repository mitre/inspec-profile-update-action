control 'SV-214353' do
  title 'The Apache web server must be protected from being stopped by a non-privileged user.'
  desc 'An attacker has at least two reasons to stop a web server. The first is to cause a denial of service (DoS), and the second is to put in place changes the attacker made to the web server configuration.

To prohibit an attacker from stopping the Apache web server, the process ID (pid) of the web server and the utilities used to start/stop it must be protected from access by non-privileged users. By knowing the "pid" and having access to the Apache web server utilities, a non-privileged user has a greater capability of stopping the server, whether intentionally or unintentionally.'
  desc 'check', %q(Right-click <'Install Path'>\bin\httpd.exe.

Click "Properties" from the "Context" menu.

Select the "Security" tab.

Review the groups and user names.

The following account may have Full control privileges:

TrustedInstaller
Web Managers
Web Manager designees

The following accounts may have read and execute, or read permissions:

Non Web Manager Administrators
ALL APPLICATION PACKAGES (built-in security group)
SYSTEM
Users

Specific users may be granted read and execute and read permissions.

Compare the local documentation authorizing specific users against the users observed when reviewing the groups and users.

If any other access is observed, this is a finding.)
  desc 'fix', "Restrict access to the web administration tool to only the Web Manager and the Web Manager's designees."
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15565r277562_chk'
  tag severity: 'medium'
  tag gid: 'V-214353'
  tag rid: 'SV-214353r879806_rule'
  tag stig_id: 'AS24-W1-000820'
  tag gtitle: 'SRG-APP-000435-WSR-000147'
  tag fix_id: 'F-15563r277563_fix'
  tag 'documentable'
  tag legacy: ['SV-102551', 'V-92463']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
