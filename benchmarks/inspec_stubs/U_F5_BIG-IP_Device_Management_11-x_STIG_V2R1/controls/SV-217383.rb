control 'SV-217383' do
  title 'The BIG-IP appliance must automatically audit account creation.'
  desc 'Upon gaining access to a network device, an attacker will often first attempt to create a persistent method of reestablishing access. One way to accomplish this is to create a new account. Notification of account creation helps to mitigate this risk. Auditing account creation provides the necessary reconciliation that account management procedures are being followed. Without this audit trail, personnel without the proper authorization may gain access to critical network nodes.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a remote authentication server that automatically audits account creation. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Authentication: User Directory" is configured for an approved remote authentication server that automatically audits account creation.

If the BIG-IP appliance is not configured to use a remote authentication server that automatically audits account creation, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use an approved remote authentication server that automatically audits the creation of accounts.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18608r290703_chk'
  tag severity: 'medium'
  tag gid: 'V-217383'
  tag rid: 'SV-217383r557520_rule'
  tag stig_id: 'F5BI-DM-000019'
  tag gtitle: 'SRG-APP-000026-NDM-000208'
  tag fix_id: 'F-18606r290704_fix'
  tag 'documentable'
  tag legacy: ['SV-74533', 'V-60103']
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
