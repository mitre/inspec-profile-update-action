control 'SV-228995' do
  title 'The BIG-IP appliance must be configured to generate alerts that can be forwarded to the administrators and Information System Security Officer (ISSO) when accounts are created.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply create a new account. Notification of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail that documents the creation of accounts and notifies administrators and the ISSO. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.'
  desc 'check', 'Verify the BIG-IP appliance is configured to generate alerts that can be forwarded to the administrators and ISSO when accounts are created. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify that "User Directory" is set to an approved authentication server type that generates alerts that can be forwarded to the administrators and ISSO when accounts are created. 

If the BIG-IP appliance is not configured to use an authentication server that would perform this function, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use a properly configured authentication server to send a notification message to the administrators and ISSO when accounts are created.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31310r518030_chk'
  tag severity: 'medium'
  tag gid: 'V-228995'
  tag rid: 'SV-228995r879887_rule'
  tag stig_id: 'F5BI-DM-000155'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31287r518031_fix'
  tag 'documentable'
  tag legacy: ['SV-74607', 'V-60177']
  tag cci: ['CCI-000366', 'CCI-001683']
  tag nist: ['CM-6 b', 'AC-2 (4)']
end
