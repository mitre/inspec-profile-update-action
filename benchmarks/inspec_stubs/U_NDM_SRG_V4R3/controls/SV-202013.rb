control 'SV-202013' do
  title 'The network device must automatically audit account creation.'
  desc 'Upon gaining access to a network device, an attacker will often first attempt to create a persistent method of reestablishing access. One way to accomplish this is to create a new account. Notification of account creation helps to mitigate this risk. Auditing account creation provides the necessary reconciliation that account management procedures are being followed. Without this audit trail, personnel without the proper authorization may gain access to critical network nodes.'
  desc 'check', 'Review the network device configuration to determine if it automatically audits account creation or is configured to use an authentication server which would perform this function. If account creation is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the network device or its associated authentication server to automatically audit the creation of accounts.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2139r381569_chk'
  tag severity: 'medium'
  tag gid: 'V-202013'
  tag rid: 'SV-202013r879525_rule'
  tag stig_id: 'SRG-APP-000026-NDM-000208'
  tag gtitle: 'SRG-APP-000026'
  tag fix_id: 'F-2140r381570_fix'
  tag 'documentable'
  tag legacy: ['SV-69289', 'V-55043']
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
