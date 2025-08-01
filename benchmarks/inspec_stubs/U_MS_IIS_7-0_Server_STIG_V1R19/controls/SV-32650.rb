control 'SV-32650' do
  title 'Unspecified file extensions must not be allowed to execute on the production web server.'
  desc 'By allowing unspecified file extensions to execute, the web servers attack surface is significantly increased.  This increased risk can be reduced by only allowing specific ISAPI extensions or CGI extensions to run on the web server.'
  desc 'check', '1. Open the IIS Manager.
2. Click the Server.
3. Double-click the ISAPI and CGI restrictions icon.
4. Click Edit Feature Settings and verify the CGI and ISAPI Modules are NOT checked. If they are checked, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the Server.
3. Double-click the ISAPI and CGI restrictions icon.
4. Click Edit Feature Settings and uncheck the CGI and ISAPI Modules check boxes.'
  impact 0.5
  ref 'DPMS Target IIS Installation 7'
  tag check_id: 'C-32871r1_chk'
  tag severity: 'medium'
  tag gid: 'V-25999'
  tag rid: 'SV-32650r2_rule'
  tag stig_id: 'WA000-WI6100'
  tag gtitle: 'WA000-WI6100'
  tag fix_id: 'F-29023r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
