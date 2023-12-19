control 'SV-33506' do
  title 'Dial-up and Hang up Options for Outlook must be configured.'
  desc 'By default, users can connect to their e-mail servers using dial-up networking if their accounts are configured appropriately. Dial-up connections are often used by mobile users who need to connect to the Internet from remote locations. Remote connections are generally not subject to the same restrictions as enterprise network environments, which can make them more vulnerable to attack.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Mail Setup “Dial–up options” must be set to “Enabled” and Hang up when finished sending, receiving, or updating is selected.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\options\\mail

Criteria: If the value Hangup after Spool is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Mail Setup “Dial–up options” to “Enabled” and Hang up when finished sending, receiving, or updating is selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-33992r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17585'
  tag rid: 'SV-33506r1_rule'
  tag stig_id: 'DTOO226 - Outlook'
  tag gtitle: 'DTOO226 - Dial-up Options'
  tag fix_id: 'F-29681r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001150']
  tag nist: ['SC-15 a']
end
