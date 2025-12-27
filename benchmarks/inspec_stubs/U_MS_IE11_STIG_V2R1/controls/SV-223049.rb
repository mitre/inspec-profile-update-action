control 'SV-223049' do
  title 'Enabling outdated ActiveX controls for Internet Explorer must be blocked.'
  desc 'This feature keeps ActiveX controls up to date and helps make them safer to use in Internet Explorer. Many ActiveX controls are not automatically updated as new versions are released. It is very important to keep ActiveX controls up to date because malicious or compromised webpages can target security flaws in out-of-date ActiveX controls.'
  desc 'check', 'In the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Security Features >> Add-on Management, verify "Turn off blocking of outdated ActiveX controls for Internet Explorer" is set to “Disabled”. 

Use the Windows Registry Editor to navigate to the following key: 

HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Ext 

If the value "VersionCheckEnabled" is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'In the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Security Features >> Add-on Management, set "Turn off blocking of outdated ActiveX controls for Internet Explorer" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24722r428697_chk'
  tag severity: 'medium'
  tag gid: 'V-223049'
  tag rid: 'SV-223049r428699_rule'
  tag stig_id: 'DTBI1110-IE11'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24710r428698_fix'
  tag 'documentable'
  tag legacy: ['SV-87397', 'V-72759']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
