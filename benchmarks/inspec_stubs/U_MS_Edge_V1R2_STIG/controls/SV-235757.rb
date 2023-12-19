control 'SV-235757' do
  title 'The HTTPS warning page must not be able to be bypassed.'
  desc 'Microsoft Edge shows a warning page when users visit sites that have SSL errors.

If this policy is enabled or not configured (default), users can click through these warning pages.

If this policy is disabled, users are blocked from clicking through any warning page.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow users to proceed from the HTTPS warning page" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "SSLErrorOverrideAllowed" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow users to proceed from the HTTPS warning page" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38976r626467_chk'
  tag severity: 'medium'
  tag gid: 'V-235757'
  tag rid: 'SV-235757r626523_rule'
  tag stig_id: 'EDGE-00-000044'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-38939r626468_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
