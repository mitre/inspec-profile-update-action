control 'SV-235767' do
  title "A website's ability to query for payment methods must be disabled."
  desc 'This setting determines whether websites can check if the user has payment methods saved.

If this policy is disabled, websites that use "PaymentRequest.canMakePayment" or "PaymentRequest.hasEnrolledInstrument" API will be informed that no payment methods are available.

If this policy is enabled or is not set, websites can check to determine if the user has payment methods saved.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow websites to query for available payment methods" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for PaymentMethodQueryEnabled is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow websites to query for available payment methods" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38986r626497_chk'
  tag severity: 'medium'
  tag gid: 'V-235767'
  tag rid: 'SV-235767r626523_rule'
  tag stig_id: 'EDGE-00-000055'
  tag gtitle: 'SRG-APP-000149'
  tag fix_id: 'F-38949r626498_fix'
  tag 'documentable'
  tag cci: ['CCI-000389']
  tag nist: ['CM-8 a 1']
end
