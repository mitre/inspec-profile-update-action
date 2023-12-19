control 'SV-32696' do
  title 'The web-site must not allow double encoded URL requests.'
  desc 'Request filtering enables administrators to create a more granular rule set with which to allow or reject inbound web content.   By setting limits on web requests, it ensures availability of web services and mitigates the risk of buffer overflow type attacks.  When the allow double escaping option is disabled it prevents attacks that rely on double-encoded requests.'
  desc 'check', 'For each site reviewed: 
1. Open the IIS Manager.
2. Click on the site name.
3. Double-click the Request Filtering icon.
4. Click Edit Feature Settings in the Actions Pane.
If the allow double escaping checkbox is checked, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the site name under review.
3. Double-click the Request Filtering icon.
4. Click Edit Feature Settings in the Actions Pane.
5. Uncheck the allow double escaping checkbox.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32893r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26045'
  tag rid: 'SV-32696r2_rule'
  tag stig_id: 'WA000-WI6250'
  tag gtitle: 'WA000-WI6250'
  tag fix_id: 'F-29039r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
