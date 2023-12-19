control 'SV-32603' do
  title 'An application pool’s rapid fail protection must be enabled.'
  desc 'Rapid fail protection is a feature that interrogates the health of worker processes associated with web sites and web applications. It can be configured to perform a number of actions such as shutting down and restarting worker processes that have reached failure thresholds.  By not setting rapid fail protection the web server could become unstable in the event of a worker process crash potentially leaving the web server unusable.'
  desc 'check', '1. Open the IIS Manager.
2. Click the Application Pools.
3. Highlight an Application Pool to review and click Advanced Settings in the Actions Pane.
4. Scroll down to the Rapid Fail Protection section and ensure the value for Enabled is set to True. If not, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the Application Pools.
3. Highlight an Application Pool to review and click Advanced Settings in the Actions Pane.
4. Scroll down to the Rapid Fail Protection section and set the value for Enabled to True.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32864r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13711'
  tag rid: 'SV-32603r2_rule'
  tag stig_id: 'WA000-WI6034 IIS7'
  tag gtitle: 'WA000-WI6034'
  tag fix_id: 'F-29008r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
