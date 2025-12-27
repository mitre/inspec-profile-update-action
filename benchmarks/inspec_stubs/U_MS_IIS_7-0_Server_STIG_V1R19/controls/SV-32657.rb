control 'SV-32657' do
  title 'A global authorization rule to restrict access must exist on the web server.'
  desc 'Authorization rules can be configured at the server, web site, folder (including Virtual Directories), or file level.  It is recommended that URL Authorization be configured to only grant access to the necessary security principals. Configuring a global Authorization rule that restricts access ensures inheritance of the settings down through the hierarchy of web directories.  This will ensure access to current and future content is only granted to the appropriate principals, mitigating risk of unauthorized access.'
  desc 'check', '1. Open the IIS Manager.
2. Click the Server.
3. Double-click the Authorization Rules icon.
4. If any user other then Administrator is listed, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the Server.
3. Double-click the Authorization Rules icon.
4. Remove all users other than Administrator.'
  impact 0.3
  ref 'DPMS Target IIS Installation 7'
  tag check_id: 'C-32874r1_chk'
  tag severity: 'low'
  tag gid: 'V-26006'
  tag rid: 'SV-32657r2_rule'
  tag stig_id: 'WA000-WI6120'
  tag gtitle: 'WA000-WI6120'
  tag fix_id: 'F-29025r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
