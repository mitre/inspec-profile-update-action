control 'SV-59707' do
  title 'Deleting websites that the user has visited must be disallowed.'
  desc 'This policy prevents users from deleting the history of websites the user has visited. If you enable this policy setting, websites the user has visited will be preserved when the user clicks "Delete". If you disable this policy setting, websites that the user has visited will be deleted when the user clicks "Delete". If you do not configure this policy setting, the user will be able to select whether to delete or preserve websites the user visited when the user clicks "Delete".'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Delete Browsing History -> 'Prevent Deleting Web sites that the User has Visited' must be 'Enabled'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Internet Explorer\Privacy Criteria: If the value "CleanHistory" is REG_DWORD = 0, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Delete Browsing History -> 'Prevent Deleting Web sites that the User has Visited' to 'Enabled'."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49919r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46841'
  tag rid: 'SV-59707r1_rule'
  tag stig_id: 'DTBI770-IE11'
  tag gtitle: 'DTBI770-IE11-Website visit history'
  tag fix_id: 'F-50579r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
