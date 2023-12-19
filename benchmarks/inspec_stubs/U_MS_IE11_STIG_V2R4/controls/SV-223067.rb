control 'SV-223067' do
  title 'Userdata persistence must be disallowed (Restricted Sites zone).'
  desc "Userdata persistence must have a level of protection based upon the site being accessed. This policy setting allows you to manage the preservation of information in the browser's history, in Favorites, in an XML store, or directly within a web page saved to disk. When a user returns to a persisted page, the state of the page can be restored if this policy setting is not appropriately configured."
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Userdata persistence' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "1606" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Userdata persistence' to 'Enabled', and select 'Disable' from the drop-down box"
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24740r428751_chk'
  tag severity: 'medium'
  tag gid: 'V-223067'
  tag rid: 'SV-223067r879642_rule'
  tag stig_id: 'DTBI132-IE11'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-24728r428752_fix'
  tag 'documentable'
  tag legacy: ['SV-59465', 'V-46601']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
