control 'SV-51981' do
  title 'Group Policies must be refreshed in the background if the user is logged on.'
  desc 'If this setting is enabled, then Group Policy settings are not refreshed while a user is currently logged on. This could lead to instances when a user does not have the latest changes to a policy applied and is therefore operating in an insecure context.'
  desc 'check', 'Review the registry.
If the following registry value does not exist, this is not a finding (this is the expected result from configuring the policy as outlined in the Fix section).
If the following registry value exists but is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\system\\

Value Name: DisableBkGndGroupPolicy

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Group Policy -> "Turn off background refresh of Group Policy" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-46894r2_chk'
  tag severity: 'medium'
  tag gid: 'V-3469'
  tag rid: 'SV-51981r1_rule'
  tag stig_id: 'WINCC-000029'
  tag gtitle: 'Group Policy - Do Not Turn off Background Refresh'
  tag fix_id: 'F-45015r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
