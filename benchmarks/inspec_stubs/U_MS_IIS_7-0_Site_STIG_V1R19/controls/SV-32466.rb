control 'SV-32466' do
  title 'Directory Browsing must be disabled.'
  desc 'The Directory Browsing feature can be used to facilitate a directory traversal exploit. Directory browsing must be disabled.'
  desc 'check', '1. Open the IIS Manager.
2. Click the site name under review.
3. Click Directory browsing icon.
4. In the Actions Pane ensure Directory Browsing is disabled. If not, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the site name under review.
3. Click Directory browsing icon.
4. Click Disable in the Actions Pane to disable Directory Browsing.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32785r3_chk'
  tag severity: 'medium'
  tag gid: 'V-6755'
  tag rid: 'SV-32466r3_rule'
  tag stig_id: 'WA000-WI090 IIS7'
  tag gtitle: 'WA000-WI090'
  tag fix_id: 'F-28974r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
