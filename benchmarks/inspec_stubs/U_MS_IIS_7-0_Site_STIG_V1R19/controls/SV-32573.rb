control 'SV-32573' do
  title 'The maximum queue length for HTTP.sys must be managed.'
  desc 'In order to determine the possible causes of client connection errors and to conserve system resources, it is important to both log errors and manage those settings controlling requests to the application pool.'
  desc 'check', '1. Open the IIS Manager.
2. Click the Application Pools.
3. Highlight an Application Pool to review and click Advanced Settings in the Actions Pane.
4. Scroll down to the General section and ensure the value for Queue Length is set to 1000. If not, this is a finding.

NOTE: If the site has operational reasons to set Queue Length to an alternate value, and has supporting documentation signed by the ISSO, this is not a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the Application Pools.
3. Highlight an Application Pool to review and click Advanced Settings in the Actions Pane.
4. Scroll down to the General section and set the value for Queue Length to 1000.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32858r2_chk'
  tag severity: 'medium'
  tag gid: 'V-13709'
  tag rid: 'SV-32573r3_rule'
  tag stig_id: 'WA000-WI6030 IIS7'
  tag gtitle: 'WA000-WI6030'
  tag fix_id: 'F-28993r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
