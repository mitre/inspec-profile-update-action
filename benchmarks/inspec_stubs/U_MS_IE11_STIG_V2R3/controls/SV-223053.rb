control 'SV-223053' do
  title 'VBScript must not be allowed to run in Internet Explorer (Internet zone).'
  desc 'This policy setting allows the management of whether VBScript can be run on pages from the specified zone in Internet Explorer. By selecting "Enable" in the drop-down box, VBScript can run without user intervention. By selecting "Prompt" in the drop-down box, users are asked to choose whether to allow VBScript to run. By selecting "Disable" in the drop-down box, VBScript is prevented from running. If this policy setting is not configured or disabled, VBScript will run without user intervention.'
  desc 'check', 'The policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Internet Zone >> "Allow VBScript to run in Internet Explorer" must be "Enabled", and "Disable" must be selected from the drop-down box. 

Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3

If the value for "140C" is not REG_DWORD = 3, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Internet Zone >> "Allow VBScript to run in Internet Explorer" to "Enabled" and select "Disable" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24726r863002_chk'
  tag severity: 'medium'
  tag gid: 'V-223053'
  tag rid: 'SV-223053r863003_rule'
  tag stig_id: 'DTBI1125-IE11'
  tag gtitle: 'SRG-APP-000209'
  tag fix_id: 'F-24714r428710_fix'
  tag 'documentable'
  tag legacy: ['SV-89849', 'V-75169']
  tag cci: ['CCI-001169']
  tag nist: ['SC-18 (3)']
end
