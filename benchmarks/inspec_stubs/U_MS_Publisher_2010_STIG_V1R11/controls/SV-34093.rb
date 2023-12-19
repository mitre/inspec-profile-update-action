control 'SV-34093' do
  title 'The Publisher Automation Security Level must be configured for high security.'
  desc 'When a separate application is used to launch Publisher 2010 programmatically, any macros can run in the programmatically-opened application without being blocked.  Disabling or not configuring this setting could allow a malicious user to use automation to run malicious code in Publisher 2010.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Publisher 2010 -> Security “Publisher Automation Security Level” must be set to “Enabled and High (Disabled)" is selected. 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\Common\\Security 

Criteria: If the value AutomationSecurityPublisher is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Publisher 2010 -> Security “Publisher Automation Security Level” to “Enabled and High (Disabled)" is selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Publisher 2010'
  tag check_id: 'C-34495r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26708'
  tag rid: 'SV-34093r1_rule'
  tag stig_id: 'DTOO323 - Publisher'
  tag gtitle: 'DTOO323 - Publisher Automation Security Level'
  tag fix_id: 'F-30020r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
