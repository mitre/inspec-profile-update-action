control 'SV-40529' do
  title 'Ability for users to enable or disable add-ons must be enforced.'
  desc "Users often choose to install add-ons that are not permitted by an organization's security policy.  Such add-ons can pose a significant security and privacy risk to your network. This policy setting allows you to manage whether users have the ability to allow or deny add-ons through Add-On Manager.  If you enable this policy setting, users cannot enable or disable add-ons through Add-On Manager.  The only exception occurs if an add-on has been specifically entered into the 'Add-On List' policy setting in such a way as to allow users to continue to manage the add-on.  In this case, the user can still manage the add-on.  If you disable or do not configure this policy setting, the appropriate controls in the Add-On Manager will be available to the user."
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> “Do Not Allow Users to enable or Disable Add-Ons” must be “Disabled”. 

Procedure: Use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Restrictions

Criteria: If the value NoExtensionManagement does not exist or the value is set to REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> “Do Not Allow Users to enable or Disable Add-Ons” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39307r5_chk'
  tag severity: 'low'
  tag gid: 'V-14245'
  tag rid: 'SV-40529r1_rule'
  tag stig_id: 'DTBI697'
  tag gtitle: 'DTBI697 - IE - Users enable or disable add-ons'
  tag fix_id: 'F-34418r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
