control 'SV-217410' do
  title 'The BIG-IP appliance must be configured to automatically audit account-enabling actions.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Notification of account enabling is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail that documents the creation of application user accounts and notifies administrators and Information System Security Officers (ISSO). Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a properly configured remote authentication server that automatically audits account-enabling actions.

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify that "User Directory" is set to an approved authentication server type that automatically audits account-enabling actions.

If the BIG-IP appliance is not configured to use a properly configured remote authentication server to automatically audit account-enabling actions, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use a properly configured remote authentication server to automatically audit account-enabling actions.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18635r290784_chk'
  tag severity: 'medium'
  tag gid: 'V-217410'
  tag rid: 'SV-217410r557520_rule'
  tag stig_id: 'F5BI-DM-000171'
  tag gtitle: 'SRG-APP-000319-NDM-000283'
  tag fix_id: 'F-18633r290785_fix'
  tag 'documentable'
  tag legacy: ['V-60187', 'SV-74617']
  tag cci: ['CCI-002130']
  tag nist: ['AC-2 (4)']
end
