control 'SV-40708' do
  title 'Deleting web sites that the user has visited must be disallowed.'
  desc 'This policy prevents users from deleting the history of web sites the user has visited. If you enable this policy setting, web sites the user has visited will be preserved when the user clicks Delete. If you disable this policy setting, web sites that the user has visited will be deleted when user clicks Delete. If you do not configure this policy setting, the user will be able to select whether to delete or preserve web sites the user visited when the user clicks Delete.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Delete Browsing History -> “Prevent Deleting Web sites that the User has Visited” must be “Enabled”. 

Procedure: Use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Privacy 

Criteria: If the value CleanHistory is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Delete Browsing History -> “Prevent Deleting Web sites that the User has Visited” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39436r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22149'
  tag rid: 'SV-40708r1_rule'
  tag stig_id: 'DTBI770'
  tag gtitle: 'DTBI770 - Web site visit history'
  tag fix_id: 'F-34564r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
