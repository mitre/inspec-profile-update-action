control 'SV-223026' do
  title 'Clipboard operations via script must be disallowed (Internet zone).'
  desc 'A malicious script could use the clipboard in an undesirable manner, for example, if the user had recently copied confidential information to the clipboard while editing a document, a malicious script could harvest that information. It might be possible to exploit other vulnerabilities in order to send the harvested data to the attacker. Allow paste operations via script must have a level of protection based upon the site being accessed.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> 'Allow cut, copy or paste operations from the clipboard via script' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 Criteria: If the value "1407" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> 'Allow cut, copy or paste operations from the clipboard via script' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24699r428628_chk'
  tag severity: 'medium'
  tag gid: 'V-223026'
  tag rid: 'SV-223026r428630_rule'
  tag stig_id: 'DTBI044-IE11'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24687r428629_fix'
  tag 'documentable'
  tag legacy: ['SV-59385', 'V-46521']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
