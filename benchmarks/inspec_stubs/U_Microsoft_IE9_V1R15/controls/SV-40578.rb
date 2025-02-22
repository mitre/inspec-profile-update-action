control 'SV-40578' do
  title 'Clipboard operations via script must be disallowed (Internet zone).'
  desc 'A malicious script could use the clipboard in an undesirable manner, for example, if the user had recently copied confidential information to the clipboard while editing a document, a malicious script could harvest that information.  It might be possible to exploit other vulnerabilities in order to send the harvested data to the attacker.  Allow paste operations via script must have level of protection based upon the site being accessed.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> "Allow cut, copy or paste operations from the clipboard via script" must be “Enabled” and "Disable" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3 

Criteria: If the value 1407 is REG_DWORD = 3, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> "Allow cut, copy or paste operations from the clipboard via script" to “Enabled” and select "Disable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39337r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6260'
  tag rid: 'SV-40578r1_rule'
  tag stig_id: 'DTBI044'
  tag gtitle: 'DTBI044 - Paste operations via script - Internet'
  tag fix_id: 'F-34445r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
