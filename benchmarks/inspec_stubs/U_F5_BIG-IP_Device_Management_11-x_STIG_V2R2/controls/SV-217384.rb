control 'SV-217384' do
  title 'The BIG-IP appliance must automatically audit account modification.'
  desc 'Since the accounts in the network device are privileged or system-level accounts, account management is vital to the security of the network device. Account management by a designated authority ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel with the appropriate and necessary privileges. Auditing account modification along with an automatic notification to appropriate individuals will provide the necessary reconciliation that account management procedures are being followed. If modifications to management accounts are not audited, reconciliation of account management procedures cannot be tracked.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a remote authentication server that automatically audits account modifications. 

Verify the BIG-IP appliance is configured to utilize a properly configured authentication server. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Authentication: User Directory" is configured to use an approved remote authentication server that automatically audits account modification.

If account modification is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use an approved authentication server that automatically audits account modifications.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18609r290706_chk'
  tag severity: 'medium'
  tag gid: 'V-217384'
  tag rid: 'SV-217384r879526_rule'
  tag stig_id: 'F5BI-DM-000021'
  tag gtitle: 'SRG-APP-000027-NDM-000209'
  tag fix_id: 'F-18607r290707_fix'
  tag 'documentable'
  tag legacy: ['SV-74535', 'V-60105']
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
