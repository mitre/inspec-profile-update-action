control 'SV-32636' do
  title 'Web-site logging must be enabled.'
  desc 'A major tool in exploring the web site use, attempted use, unusual conditions, and problems are reported in the access and error logs. In the event of a security incident, these logs can provide the SA and the web manager with valuable information.'
  desc 'check', '1. Open the IIS Manager. 
2. Click the site name.
3. Double-click Logging 
4. Ensure logging is enabled. 

If logging is not enabled, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the site name.
3. Double-click Logging.
4. Click the Enable option from the Action Pane, click apply.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-33496r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2250'
  tag rid: 'SV-32636r2_rule'
  tag stig_id: 'WG240 IIS7'
  tag gtitle: 'WG240'
  tag fix_id: 'F-29196r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
