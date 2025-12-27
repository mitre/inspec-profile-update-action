control 'SV-1145' do
  title 'Administrator automatic logon is enabled.'
  desc 'This is a category 1 finding because it will directly log on to the system with administrator privileges when the machine is rebooted.  This would give full access to any unauthorized individual who reboots the computer.

By default this setting is not enabled.  If this setting exists, it should be disabled.  If this capability exists, the password may also be present in the registry, and must be removed.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)” to “Disabled”.'
  impact 0.7
  ref 'DPMS Target Windows XP'
  tag severity: 'high'
  tag gid: 'V-1145'
  tag rid: 'SV-1145r1_rule'
  tag gtitle: 'Disable Automatic Logon'
  tag fix_id: 'F-98r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
