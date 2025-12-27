control 'SV-223025' do
  title 'Userdata persistence must be disallowed (Internet zone).'
  desc "Userdata persistence must have a level of protection based upon the site being accessed. It is possible for sites hosting malicious content to exploit this feature as part of an attack against visitors browsing the site. This policy setting allows you to manage the preservation of information in the browser's history, in Favorites, in an XML store, or directly within a web page saved to disk. When a user returns to a persisted page, the state of the page can be restored if this policy setting is not appropriately configured."
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> 'Userdata persistence' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 Criteria: If the value "1606" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> 'Userdata persistence' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24698r428625_chk'
  tag severity: 'medium'
  tag gid: 'V-223025'
  tag rid: 'SV-223025r879642_rule'
  tag stig_id: 'DTBI042-IE11'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-24686r428626_fix'
  tag 'documentable'
  tag legacy: ['SV-59381', 'V-46517']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
