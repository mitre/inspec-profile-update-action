control 'SV-229000' do
  title 'The BIG-IP appliance must be configured to generate an immediate alert for account-enabling actions.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Notification of account enabling is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail that documents the creation of application user accounts and notifies administrators and ISSOs. Such a process greatly reduces the risk that accounts will be surreptitiously enabled and provides logging that can be used for forensic purposes. 

In order to detect and respond to events that affect network administrator accessibility and device processing, network devices must audit account-enabling actions and, as required, notify the appropriate individuals so they can investigate the event.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a properly configured remote authentication server to generate an immediate alert for account-enabling actions. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify that "User Directory" is set to an approved authentication server type to generate an immediate alert for account-enabling actions.

If the BIG-IP appliance is not configured to use a properly configured remote authentication server to generate an immediate alert for account-enabling actions, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use a properly configured remote authentication server to generate an immediate alert for account-enabling actions.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31315r518045_chk'
  tag severity: 'medium'
  tag gid: 'V-229000'
  tag rid: 'SV-229000r557520_rule'
  tag stig_id: 'F5BI-DM-000173'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31292r518046_fix'
  tag 'documentable'
  tag legacy: ['SV-74619', 'V-60189']
  tag cci: ['CCI-000366', 'CCI-002132']
  tag nist: ['CM-6 b', 'AC-2 (4)']
end
