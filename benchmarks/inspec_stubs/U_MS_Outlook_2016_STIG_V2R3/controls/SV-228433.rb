control 'SV-228433' do
  title 'Outlook Object Model scripts must be disallowed to run for shared folders.'
  desc "This policy setting controls whether Outlook executes scripts associated with custom forms or folder home pages for shared folders. If you enable this policy setting, Outlook cannot execute any scripts associated with shared folders, overriding any configuration changes on users' computers. If you disable this policy setting, Outlook will automatically run any scripts associated with custom forms or folder home pages for shared folders. If you do not configure this policy setting, the behavior is the equivalent of setting the policy to Enabled."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Outlook Options -> Other -> Advanced "Do not allow Outlook object model scripts to run for shared folders" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security

Criteria: If the value SharedFolderScript is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Outlook Options -> Other -> Advanced "Do not allow Outlook object model scripts to run for shared folders" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30666r497621_chk'
  tag severity: 'medium'
  tag gid: 'V-228433'
  tag rid: 'SV-228433r508021_rule'
  tag stig_id: 'DTOO232'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-30651r497622_fix'
  tag 'documentable'
  tag legacy: ['SV-85769', 'V-71145']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
