control 'SV-235772' do
  title 'Guest mode must be disabled.'
  desc 'Enabling Guest mode allows the use of guest profiles in Microsoft Edge. In a guest profile, the browser does not import browsing data from existing profiles, and it deletes browsing data when all guest profiles are closed.

If this policy is enabled or not configured, Microsoft Edge lets users browse in guest profiles.

If this policy is disabled, Microsoft Edge does not let users browse in guest profiles.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Enable guest mode" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "BrowserGuestModeEnabled" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Enable guest mode" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38991r626512_chk'
  tag severity: 'medium'
  tag gid: 'V-235772'
  tag rid: 'SV-235772r626523_rule'
  tag stig_id: 'EDGE-00-000060'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38954r626513_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
