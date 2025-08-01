control 'SV-214440' do
  title 'Unspecified file extensions on a production IIS 8.5 web server must be removed.'
  desc 'By allowing unspecified file extensions to execute, the web servers attack surface is significantly increased. This increased risk can be reduced by only allowing specific ISAPI extensions or CGI extensions to run on the web server.'
  desc 'check', 'Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Double-click the "ISAPI and CGI restrictions" icon.

Click “Edit Feature Settings".

Verify the "Allow unspecified CGI modules" and the "Allow unspecified ISAPI modules" check boxes are NOT checked.

If either or both of the "Allow unspecified CGI modules" and the "Allow unspecified ISAPI modules" check boxes are checked, this is a finding.'
  desc 'fix', 'Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Double-click the "ISAPI and CGI restrictions" icon.

Click "Edit Feature Settings".

Remove the check from the "Allow unspecified CGI modules" and the "Allow unspecified ISAPI modules" check boxes.

Click OK.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Server'
  tag check_id: 'C-15650r310368_chk'
  tag severity: 'medium'
  tag gid: 'V-214440'
  tag rid: 'SV-214440r879887_rule'
  tag stig_id: 'IISW-SV-000158'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-15648r310369_fix'
  tag 'documentable'
  tag legacy: ['SV-91465', 'V-76769']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
