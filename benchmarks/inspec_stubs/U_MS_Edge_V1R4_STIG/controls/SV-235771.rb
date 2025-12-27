control 'SV-235771' do
  title 'The Share Experience feature must be disabled.'
  desc 'If this policy is set to "ShareAllowed" (the default), users will be able to access the Windows 10 Share experience from the Settings and More menu in Microsoft Edge to share with other apps on the system.

If this policy is set to "ShareDisallowed", users will not be able to access the Windows 10 Share experience. If the Share button is on the toolbar, it will also be hidden.

Policy options mapping:
- ShareAllowed (0) = Allow using the Share experience.
- ShareDisallowed (1) = Do not allow using the Share experience.'
  desc 'check', %q(The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Configure the Share experience" must be set to "enabled" with the option value set to "Don't allow using the Share experience".

Use the Windows Registry Editor to navigate to the following key:
HKLM\SOFTWARE\Policies\Microsoft\Edge

If the value for "ConfigureShare" is not set to "REG_DWORD = 1", this is a finding.)
  desc 'fix', %q(Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Configure the Share experience" to "Don't allow using the Share experience".)
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38990r626509_chk'
  tag severity: 'medium'
  tag gid: 'V-235771'
  tag rid: 'SV-235771r626523_rule'
  tag stig_id: 'EDGE-00-000059'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38953r626510_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
