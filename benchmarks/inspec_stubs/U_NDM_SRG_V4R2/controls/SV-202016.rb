control 'SV-202016' do
  title 'The network device must automatically audit account removal actions.'
  desc 'Account management, as a whole, ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel. Auditing account removal actions will support account management procedures. When device management accounts are terminated, user or service accessibility may be affected. Auditing also ensures authorized active accounts remain enabled and available for use when required.'
  desc 'check', 'Check the network device to determine if account removal actions are automatically audited.  This requirement may be verified by demonstration, configuration review, or validated test results.  This requirement may be met through use of a properly configured authentication server if the device is configured to use the authentication server. If account removal actions are not automatically audited, this is a finding.'
  desc 'fix', 'Configure the network device or its associated authentication server to automatically audit the removal of accounts.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2142r381578_chk'
  tag severity: 'medium'
  tag gid: 'V-202016'
  tag rid: 'SV-202016r879528_rule'
  tag stig_id: 'SRG-APP-000029-NDM-000211'
  tag gtitle: 'SRG-APP-000029'
  tag fix_id: 'F-2143r381579_fix'
  tag 'documentable'
  tag legacy: ['SV-69295', 'V-55049']
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
