control 'SV-239899' do
  title 'The Cisco ASA must be configured to automatically audit account disabling actions.'
  desc 'Account management, as a whole, ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel. Auditing account disabling actions will support account management procedures. When device management accounts are disabled, user or service accessibility may be affected. Auditing also ensures authorized active accounts remain enabled and available for use when required.'
  desc 'check', 'Review the ASA configuration to determine if it automatically audits account disabling. The configuration should look similar to the example below:

logging enable
logging buffered informational

Note: The ASA will log all EXEC-mode commands.

If account disabling is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the ASA to log account disabling using the following commands:

ASA(config)# logging enable
ASA(config)# logging buffered informational
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43132r666058_chk'
  tag severity: 'medium'
  tag gid: 'V-239899'
  tag rid: 'SV-239899r666060_rule'
  tag stig_id: 'CASA-ND-000110'
  tag gtitle: 'SRG-APP-000028-NDM-000210'
  tag fix_id: 'F-43091r666059_fix'
  tag 'documentable'
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']
end
