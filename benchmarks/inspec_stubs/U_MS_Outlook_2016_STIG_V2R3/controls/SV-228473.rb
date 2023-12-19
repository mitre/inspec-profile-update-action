control 'SV-228473' do
  title 'Outlook must be configured not to prompt users to choose security settings if default settings fail.'
  desc 'Check to prompt the user to choose security settings if default settings fail; uncheck to automatically select.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security "Prompt user to choose security settings if default settings fail" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security

Criteria: If the value ForceDefaultProfile is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security "Prompt user to choose security settings if default settings fail" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30706r497741_chk'
  tag severity: 'medium'
  tag gid: 'V-228473'
  tag rid: 'SV-228473r508021_rule'
  tag stig_id: 'DTOO315'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30691r497742_fix'
  tag 'documentable'
  tag legacy: ['SV-85895', 'V-71271']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
