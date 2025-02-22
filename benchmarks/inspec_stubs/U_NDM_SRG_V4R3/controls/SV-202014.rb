control 'SV-202014' do
  title 'The network device must automatically audit account modification.'
  desc 'Since the accounts in the network device are privileged or system-level accounts, account management is vital to the security of the network device. Account management by a designated authority ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel with the appropriate and necessary privileges. Auditing account modification along with an automatic notification to appropriate individuals will provide the necessary reconciliation that account management procedures are being followed. If modifications to management accounts are not audited, reconciliation of account management procedures cannot be tracked.'
  desc 'check', 'Check the network device to determine if account modification actions are automatically audited.  This requirement may be verified by demonstration, configuration review, or validated test results.  This requirement may be met through use of a properly configured authentication server if the device is configured to use the authentication server. If account modification is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the network device or its associated authentication server to automatically audit the modification of accounts.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2140r381572_chk'
  tag severity: 'medium'
  tag gid: 'V-202014'
  tag rid: 'SV-202014r879526_rule'
  tag stig_id: 'SRG-APP-000027-NDM-000209'
  tag gtitle: 'SRG-APP-000027'
  tag fix_id: 'F-2141r381573_fix'
  tag 'documentable'
  tag legacy: ['SV-69291', 'V-55045']
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
