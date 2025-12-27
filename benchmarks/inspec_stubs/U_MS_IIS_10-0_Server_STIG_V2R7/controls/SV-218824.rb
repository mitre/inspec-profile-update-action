control 'SV-218824' do
  title 'Unspecified file extensions on a production IIS 10.0 web server must be removed.'
  desc 'By allowing unspecified file extensions to execute, the web servers attack surface is significantly increased. This increased risk can be reduced by only allowing specific ISAPI extensions or CGI extensions to run on the web server.'
  desc 'check', 'Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Double-click the "ISAPI and CGI restrictions" icon.

Click “Edit Feature Settings".

Verify the "Allow unspecified CGI modules" and the "Allow unspecified ISAPI modules" check boxes are NOT checked.

If either or both of the "Allow unspecified CGI modules" and the "Allow unspecified ISAPI modules" check boxes are checked, this is a finding.'
  desc 'fix', 'Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Double-click the "ISAPI and CGI restrictions" icon.

Click "Edit Feature Settings".

Remove the check from the "Allow unspecified CGI modules" and the "Allow unspecified ISAPI modules" check boxes.

Click "OK".'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20296r310947_chk'
  tag severity: 'medium'
  tag gid: 'V-218824'
  tag rid: 'SV-218824r561041_rule'
  tag stig_id: 'IIST-SV-000158'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-20294r310948_fix'
  tag 'documentable'
  tag legacy: ['SV-109287', 'V-100183']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
