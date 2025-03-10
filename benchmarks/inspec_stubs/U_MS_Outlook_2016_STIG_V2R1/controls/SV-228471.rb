control 'SV-228471' do
  title 'User Entries to Server List must be disallowed.'
  desc 'This policy setting controls whether Outlook users can add entries to the list of SharePoint servers when establishing a meeting workspace. If you enable this policy setting, you can choose between two options to determine whether Outlook users can add entries to the published server list: - Publish default, allow others. This option is the default configuration in Outlook. - Publish default, disallow others. This option prevents users from adding servers to the default published server list. If you disable or do not configure this policy setting, when users create a meeting workspace, they can choose a server from a default list provided by administrators or manually enter the address of a server that is not listed. This is the equivalent of Enabled -- Publish default, allow others.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Meeting Workspace "Disable user entries to server list" is set to "Enabled (Publish default, disallow others)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\meetings\\profile

Criteria: If the value ServerUI is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Meeting Workspace "Disable user entries to server list" to "Enabled (Publish default, disallow others)".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30704r497735_chk'
  tag severity: 'medium'
  tag gid: 'V-228471'
  tag rid: 'SV-228471r508021_rule'
  tag stig_id: 'DTOO286'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-30689r497736_fix'
  tag 'documentable'
  tag legacy: ['SV-85889', 'V-71265']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
