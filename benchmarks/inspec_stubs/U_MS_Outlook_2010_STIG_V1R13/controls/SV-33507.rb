control 'SV-33507' do
  title 'Outlook Dial-up options to Warn user before allowing switch in dial-up access must be configured.'
  desc 'Users can connect to their e-mail servers using dial-up networking if their accounts are configured appropriately. Dial-up connections are often used by mobile users who need to connect to the Internet from remote locations. Remote connections are generally not subject to the same restrictions as enterprise network environments, which can make them more vulnerable to attack.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Mail Setup “Dial–up options” must be set to “Enabled” and Warn before switching dial-up connection is selected.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\options\\mail

Criteria: If the value Warn on Dialup is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Mail Setup “Dial–up options” to “Enabled” and Warn before switching dial-up connection is selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-33993r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17586'
  tag rid: 'SV-33507r1_rule'
  tag stig_id: 'DTOO225 - Outlook'
  tag gtitle: 'DTOO225 - Warn before Switching Dial-up'
  tag fix_id: 'F-29682r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
