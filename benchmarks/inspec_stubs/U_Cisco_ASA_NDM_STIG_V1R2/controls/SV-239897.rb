control 'SV-239897' do
  title 'The Cisco ASA must be configured to automatically audit account creation.'
  desc 'Upon gaining access to a network device, an attacker will often first attempt to create a persistent method of reestablishing access. One way to accomplish this is to create a new account. Notification of account creation helps to mitigate this risk. Auditing account creation provides the necessary reconciliation that account management procedures are being followed. Without this audit trail, personnel without the proper authorization may gain access to critical network nodes.'
  desc 'check', 'Review the ASA configuration to determine if it automatically audits account creation. The configuration should look similar to the example below:

logging enable
logging buffered informational

Note: The ASA will log all EXEC-mode commands.

If account creation is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the ASA to log account creation using the following commands:

ASA(config)# logging enable
ASA(config)# logging buffered informational
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43130r666052_chk'
  tag severity: 'medium'
  tag gid: 'V-239897'
  tag rid: 'SV-239897r666054_rule'
  tag stig_id: 'CASA-ND-000090'
  tag gtitle: 'SRG-APP-000026-NDM-000208'
  tag fix_id: 'F-43089r666053_fix'
  tag 'documentable'
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
