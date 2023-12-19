control 'SV-34106' do
  title 'Outlook must be configured not to prompt users to choose security settings if default settings fail.'
  desc 'Prompts the user to choose security settings if default settings fail; uncheck to automatically select.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security “Prompt user to choose security settings if default settings fail” must be set to “Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\security

Criteria: If the value ForceDefaultProfile is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security “Prompt user to choose security settings if default settings fail” to “Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34231r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26635'
  tag rid: 'SV-34106r1_rule'
  tag stig_id: 'DTOO315 - Outlook'
  tag gtitle: 'DTOO315 - Outlook Security settings'
  tag fix_id: 'F-29921r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
