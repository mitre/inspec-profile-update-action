control 'SV-3469' do
  title 'The system is configured to prevent background refresh of Group Policy.'
  desc 'If this setting is enabled, then Group Policy settings are not refreshed while a user is currently logged on.  This could lead to instances when a user does not have the latest changes to a policy applied and is therefore operating in an insecure context.'
  desc 'fix', 'Configure the system to require Group Policy background refresh by setting the policy value for Computer Configuration -> Administrative Templates -> System -> Group Policy “Turn Off Background Refresh of Group Policy”  to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-3469'
  tag rid: 'SV-3469r2_rule'
  tag gtitle: 'Group Policy - Do Not Turn off Background Refresh'
  tag fix_id: 'F-5684r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
