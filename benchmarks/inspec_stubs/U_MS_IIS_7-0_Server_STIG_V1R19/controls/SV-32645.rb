control 'SV-32645' do
  title 'Directory Browsing must be disabled on the production web server.'
  desc 'Directory browsing allows the contents of a directory to be displayed upon request from a web client. If directory browsing is enabled for a directory in IIS, users could receive a web page listing the contents of the directory.  If directory browsing is enabled the risk of inadvertently disclosing sensitive content is increased.'
  desc 'check', '1. Open the IIS Manager.
2. Click the Server.
3. Double-click the Directory Browsing icon.
4. Under the Actions Pane verify Directory Browsing is disabled. If not, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the Server.
3. Double-click the Directory Browsing icon.
4. Under the Actions Pane click Disabled.'
  impact 0.3
  ref 'DPMS Target IIS Installation 7'
  tag check_id: 'C-32869r1_chk'
  tag severity: 'low'
  tag gid: 'V-25994'
  tag rid: 'SV-32645r2_rule'
  tag stig_id: 'WA000-WI091'
  tag gtitle: 'WA000-WI091'
  tag fix_id: 'F-29021r1_fix'
  tag 'documentable'
end
