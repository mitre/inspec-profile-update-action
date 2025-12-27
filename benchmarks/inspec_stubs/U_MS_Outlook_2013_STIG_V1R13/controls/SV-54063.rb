control 'SV-54063' do
  title 'Outlook must be configured not to prompt users to choose security settings if default settings fail.'
  desc 'This policy prompts the user to choose security settings if default settings fail, but allowing users to select their own security settings would result in inconsistent enforcement in the organization and the likelihood of nonsecure settings being applied.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security "Prompt user to choose security settings if default settings fail" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\security

Criteria: If the value ForceDefaultProfile is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security "Prompt user to choose security settings if default settings fail" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-48003r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26635'
  tag rid: 'SV-54063r1_rule'
  tag stig_id: 'DTOO315'
  tag gtitle: 'DTOO315 - Outlook Security settings'
  tag fix_id: 'F-46943r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
