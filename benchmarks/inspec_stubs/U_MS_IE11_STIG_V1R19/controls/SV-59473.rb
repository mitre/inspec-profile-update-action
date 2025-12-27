control 'SV-59473' do
  title 'Configuring History setting must be set to 40 days.'
  desc 'This setting specifies the number of days that Internet Explorer keeps track of the pages viewed in the History List. The delete Browsing History option can be accessed using Tools, Internet Options, "General" tab, and then click Settings under Browsing History. If you enable this policy setting, a user cannot set the number of days that Internet Explorer keeps track of the pages viewed in the History List. The number of days that Internet Explorer keeps track of the pages viewed in the History List must be specified. Users will not be able to delete browsing history. If you disable or do not configure this policy setting, a user can set the number of days that Internet Explorer tracks views of pages in the History List. Users can delete browsing history.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Delete Browsing History -> 'Disable Configuring History' must be 'Enabled', and '40' entered in 'Days to keep pages in History'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Internet Explorer\Control Panel Criteria: If the value "History" is REG_DWORD = 1, this is not a finding. AND  Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History Criteria: If the value "DaysToKeep" is REG_DWORD = 40 (decimal), this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Delete Browsing History -> 'Disable Configuring History' to 'Enabled', and enter '40' in 'Days to keep pages in History'."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49775r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46609'
  tag rid: 'SV-59473r1_rule'
  tag stig_id: 'DTBI300-IE11'
  tag gtitle: 'DTBI300-IE11-Configuring History lists'
  tag fix_id: 'F-50379r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
