control 'SV-239900' do
  title 'The Cisco ASA must be configured to automatically audit account removal actions.'
  desc 'Account management, as a whole, ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel. Auditing account removal actions will support account management procedures. When device management accounts are terminated, user or service accessibility may be affected. Auditing also ensures authorized active accounts remain enabled and available for use when required.'
  desc 'check', 'Review the ASA configuration to determine if it automatically audits account removal. The configuration should look similar to the example below:

logging enable
logging buffered informational

Note: The ASA will log all EXEC-mode commands.

If account removal is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the ASA to log account removal using the following commands:

ASA(config)# logging enable
ASA(config)# logging buffered informational
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43133r666061_chk'
  tag severity: 'medium'
  tag gid: 'V-239900'
  tag rid: 'SV-239900r879528_rule'
  tag stig_id: 'CASA-ND-000120'
  tag gtitle: 'SRG-APP-000029-NDM-000211'
  tag fix_id: 'F-43092r666062_fix'
  tag 'documentable'
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
