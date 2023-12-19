control 'SV-32344' do
  title 'The system will be configured to enable the background refresh of Group Policy.'
  desc 'If this setting is enabled, then Group Policy settings are not refreshed while a user is currently logged on.  This could lead to instances when a user does not have the latest changes to a policy applied and is therefore operating in an insecure context.'
  desc 'check', 'Review the registry.
If the following registry value does not exist, this is not a finding (This is the expected result from configuring the policy as outlined in the Fix section).
If the following registry value does exist but is not configured as specified, this is a finding.

Registry Hive:   HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\system\\

Value Name:  DisableBkGndGroupPolicy

Type:   REG_DWORD
Value:   0'
  desc 'fix', 'Configure the system to require Group Policy background refresh by setting the policy value for Computer Configuration -> Administrative Templates -> System -> Group Policy “Turn Off Background Refresh of Group Policy”  to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-40666r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3469'
  tag rid: 'SV-32344r2_rule'
  tag gtitle: 'Group Policy - Do Not Turn off Background Refresh'
  tag fix_id: 'F-5684r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
