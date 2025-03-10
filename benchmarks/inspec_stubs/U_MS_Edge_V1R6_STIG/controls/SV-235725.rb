control 'SV-235725' do
  title 'The ability of sites to show pop-ups must be disabled.'
  desc 'Set whether websites can show pop-up windows. Pop-ups can be allowed on all websites ("AllowPopups") or blocked on all sites ("BlockPopups").

If this policy is configured, pop-up windows are blocked by default, and users can change this setting.

Policy options mapping:
- AllowPopups (1) = Allow all sites to show pop-ups.
- BlockPopups (2) = Do not allow any site to show pop-ups.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Content settings/Default pop-up window setting" must be set to "Enabled" with the option value set to "Do not allow any site to show  pop-ups".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for DefaultPopupsSetting is not set to "REG_DWORD = 2", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Content settings/Default pop-up window setting" to "Enabled" with the option value set to "Do not allow any site to show  pop-ups".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38944r626371_chk'
  tag severity: 'medium'
  tag gid: 'V-235725'
  tag rid: 'SV-235725r626523_rule'
  tag stig_id: 'EDGE-00-000008'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38907r626372_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
