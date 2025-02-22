control 'SV-217404' do
  title 'The BIG-IP appliance must only store encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

Network devices must enforce password encryption using an approved cryptographic hash function, when storing passwords.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a properly configured authentication server that enforces password encryption for storage.

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Authentication: User Directory" is configured for an approved remote authentication server that only stores encrypted representations of passwords.

If the BIG-IP appliance is not configured to use a properly configured authentication server that stores encrypted representations of passwords, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use a properly configured authentication server that only stores encrypted representations of passwords.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18629r290766_chk'
  tag severity: 'medium'
  tag gid: 'V-217404'
  tag rid: 'SV-217404r557520_rule'
  tag stig_id: 'F5BI-DM-000121'
  tag gtitle: 'SRG-APP-000171-NDM-000258'
  tag fix_id: 'F-18627r290767_fix'
  tag 'documentable'
  tag legacy: ['V-60157', 'SV-74587']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
