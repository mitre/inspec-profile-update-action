control 'SV-87395' do
  title 'Run once selection for running outdated ActiveX controls must be disabled.'
  desc 'This feature keeps ActiveX controls up to date and helps make them safer to use in Internet Explorer. Many ActiveX controls are not automatically updated as new versions are released. It is very important to keep ActiveX controls up to date because malicious or compromised webpages can target security flaws in out-of-date ActiveX controls.'
  desc 'check', 'In the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Security Features >> Add-on Management, verify "Remove the Run this time button for outdated ActiveX controls in IE" is set to “Enabled”. 

Use the Windows Registry Editor to navigate to the following key: 

HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Ext 

If the value "RunThisTimeEnabled" is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'In the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Security Features >> Add-on Management, set "Remove the Run this time button for outdated ActiveX controls in IE" to "Enabled".'
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-72905r8_chk'
  tag severity: 'medium'
  tag gid: 'V-72757'
  tag rid: 'SV-87395r2_rule'
  tag stig_id: 'DTBI1105-IE11'
  tag gtitle: 'DTBI1105-IE11-Run once selection for running outdated ActiveX controls must be disabled.'
  tag fix_id: 'F-79167r7_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
