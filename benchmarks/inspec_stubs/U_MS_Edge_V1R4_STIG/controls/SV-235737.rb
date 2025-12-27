control 'SV-235737' do
  title 'Importing of payment info must be disabled.'
  desc 'Allows users to import payment info from another browser into Microsoft Edge.

If this policy is enabled, the payment info check box is automatically selected in the Import browser data dialog box.

If this policy is disabled, payment info is not imported at first run, and users cannot import it manually.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow importing of payment info" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "ImportPaymentInfo" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow importing of payment info" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38956r626407_chk'
  tag severity: 'medium'
  tag gid: 'V-235737'
  tag rid: 'SV-235737r626523_rule'
  tag stig_id: 'EDGE-00-000020'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38919r626408_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
