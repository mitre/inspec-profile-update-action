control 'SV-228996' do
  title 'The BIG-IP appliance must be configured to generate alerts that can be forwarded to the administrators and Information System Security Officer (ISSO) when accounts are modified.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply modify an existing account. Notification of account modification is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail that documents the modification of device administrator accounts and notifies administrators and the ISSO. Such a process greatly reduces the risk that accounts will be surreptitiously modified and provides logging that can be used for forensic purposes.

The network device must generate the alert. Notification may be done by a management server.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a properly configured authentication server that generates alerts that can be forwarded to the administrators and ISSO when accounts are modified. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify that "User Directory" is set to an approved authentication server type that generates alerts that can be forwarded to the administrators and ISSO when accounts are modified. 

If the BIG-IP appliance is not configured to use an authentication server that would perform this function, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use a properly configured authentication server to send a notification message to the administrators and ISSO when accounts are modified.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31311r518033_chk'
  tag severity: 'medium'
  tag gid: 'V-228996'
  tag rid: 'SV-228996r557520_rule'
  tag stig_id: 'F5BI-DM-000157'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31288r518034_fix'
  tag 'documentable'
  tag legacy: ['V-60179', 'SV-74609']
  tag cci: ['CCI-000366', 'CCI-001684']
  tag nist: ['CM-6 b', 'AC-2 (4)']
end
