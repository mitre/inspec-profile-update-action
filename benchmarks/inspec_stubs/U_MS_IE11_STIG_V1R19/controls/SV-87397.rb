control 'SV-87397' do
  title 'Enabling outdated ActiveX controls for Internet Explorer must be blocked.'
  desc 'This feature keeps ActiveX controls up to date and helps make them safer to use in Internet Explorer. Many ActiveX controls are not automatically updated as new versions are released. It is very important to keep ActiveX controls up to date because malicious or compromised webpages can target security flaws in out-of-date ActiveX controls.'
  desc 'check', 'In the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Security Features >> Add-on Management, verify "Turn off blocking of outdated ActiveX controls for Internet Explorer" is set to “Disabled”. 

Use the Windows Registry Editor to navigate to the following key: 

HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Ext 

If the value "VersionCheckEnabled" is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'In the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Security Features >> Add-on Management, set "Turn off blocking of outdated ActiveX controls for Internet Explorer" to "Disabled".'
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-72907r6_chk'
  tag severity: 'medium'
  tag gid: 'V-72759'
  tag rid: 'SV-87397r2_rule'
  tag stig_id: 'DTBI1110-IE11'
  tag gtitle: 'DTBI1110-IE11-Enabling outdated ActiveX controls for Internet Explorer must be blocked.'
  tag fix_id: 'F-79169r5_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
