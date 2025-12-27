control 'SV-235746' do
  title 'Autofill for addresses must be disabled.'
  desc 'Enables the AutoFill feature and allows users to auto-complete address information in web forms using previously stored information.

If this policy is disabled, AutoFill never suggests or fills credit card information, nor will it save additional credit card information that users might submit while browsing the web.

If this policy is enabled or not configured, users can control AutoFill for addresses in the user interface.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Enable AutoFill for addresses" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "AutofillAddressEnabled" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Enable AutoFill for addresses" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38965r626434_chk'
  tag severity: 'medium'
  tag gid: 'V-235746'
  tag rid: 'SV-235746r626523_rule'
  tag stig_id: 'EDGE-00-000029'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38928r626435_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
