control 'SV-202015' do
  title 'The network device must automatically audit account disabling actions.'
  desc 'Account management, as a whole, ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel. Auditing account disabling actions will support account management procedures. When device management accounts are disabled, user or service accessibility may be affected. Auditing also ensures authorized active accounts remain enabled and available for use when required.'
  desc 'check', 'Check the network device to determine if account disabling actions are automatically audited.  This requirement may be verified by demonstration, configuration review, or validated test results.  This requirement may be met through use of a properly configured authentication server if the device is configured to use the authentication server. If account disabling actions are not audited, this is a finding.'
  desc 'fix', 'Configure the network device or its associated authentication server to automatically audit the disabling of accounts.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2141r381575_chk'
  tag severity: 'medium'
  tag gid: 'V-202015'
  tag rid: 'SV-202015r879527_rule'
  tag stig_id: 'SRG-APP-000028-NDM-000210'
  tag gtitle: 'SRG-APP-000028'
  tag fix_id: 'F-2142r381576_fix'
  tag 'documentable'
  tag legacy: ['SV-69293', 'V-55047']
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']
end
