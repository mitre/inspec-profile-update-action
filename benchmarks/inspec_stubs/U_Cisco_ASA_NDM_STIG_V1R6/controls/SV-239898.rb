control 'SV-239898' do
  title 'The Cisco ASA must be configured to automatically audit account modification.'
  desc 'Since the accounts in the network device are privileged or system-level accounts, account management is vital to the security of the network device. Account management by a designated authority ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel with the appropriate and necessary privileges. Auditing account modification along with an automatic notification to appropriate individuals will provide the necessary reconciliation that account management procedures are being followed. If modifications to management accounts are not audited, reconciliation of account management procedures cannot be tracked.'
  desc 'check', 'Review the ASA configuration to determine if it automatically audits account modification. The configuration should look similar to the example below:

logging enable
logging buffered informational

Note: The ASA will log all EXEC-mode commands.

If account modification is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the ASA to log account modification using the following commands:

ASA(config)# logging enable
ASA(config)# logging buffered informational
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43131r666055_chk'
  tag severity: 'medium'
  tag gid: 'V-239898'
  tag rid: 'SV-239898r879526_rule'
  tag stig_id: 'CASA-ND-000100'
  tag gtitle: 'SRG-APP-000027-NDM-000209'
  tag fix_id: 'F-43090r666056_fix'
  tag 'documentable'
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
