control 'SV-235741' do
  title 'Autoplay must be disabled.'
  desc 'This policy sets the media autoplay policy for websites.

The default setting, "Not configured" respects the current media autoplay settings and lets users configure their autoplay settings.

Setting to "Enabled" sets media autoplay to "Allow". All websites are allowed to autoplay media. Users cannot override this policy.

Setting to "Disabled" sets media autoplay to "Block". No websites are allowed to autoplay media. Users cannot override this policy.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow media autoplay for websites" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "AutoplayAllowed" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow media autoplay for websites" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38960r626419_chk'
  tag severity: 'medium'
  tag gid: 'V-235741'
  tag rid: 'SV-235741r626523_rule'
  tag stig_id: 'EDGE-00-000024'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38923r626420_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
