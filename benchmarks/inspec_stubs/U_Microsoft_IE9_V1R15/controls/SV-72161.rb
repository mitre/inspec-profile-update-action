control 'SV-72161' do
  title 'The IE home page is not set to blank or a trusted site.'
  desc 'By setting this parameter appropriately, a malicious web site will not be automatically loaded into a browser which may contain mobile code.'
  desc 'check', 'The policy for User Configuration -> Policies -> Administrative Templates -> Windows Components -> Internet Explorer "Disable changing home page settings" must be "Enable" and specify the URL for the home page.

Procedure:  Use the Windows Registry Editor to navigate to the following key: HKCU\\Software\\Microsoft\\Internet Explorer\\Main

Criteria: If the value Start Page is about:blank or a trusted site this is not a finding.'
  desc 'fix', 'Set the policy for User Configuration -> Policies -> Administrative Templates -> Windows Components -> Internet Explorer "Disable changing home page settings" to "Enable" and specify the URL for the home page.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-170r4_chk'
  tag severity: 'medium'
  tag gid: 'V-6228'
  tag rid: 'SV-72161r2_rule'
  tag stig_id: 'DTBI001'
  tag gtitle: 'DTBI001 - The IE home page is not set correctly'
  tag fix_id: 'F-131r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCMC-1'
end
