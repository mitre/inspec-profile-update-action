control 'SV-213433' do
  title 'Windows Defender AV must be configured to check in real time with MAPS before content is run or accessed.'
  desc 'This feature ensures the device checks in real time with the Microsoft Active Protection Service (MAPS) before allowing certain content to be run or accessed. If this feature is disabled the check will not occur which will lower the protection state of the device. Enabled - The Block at First Sight setting is turned on. Disabled - The Block at First Sight setting is turned off. This feature requires these Group Policy settings to be set as follows: MAPS -> The "Join Microsoft MAPS" must be enabled or the "Block at First Sight" feature will not function. MAPS -> The "Send file samples when further analysis is required" should be set to 1 (Send safe samples) or 3 (Send all samples). Setting to 0 (Always Prompt) will lower the protection state of the device.  Setting to 2 (Never send) means the "Block at First Sight" feature will not function. Real-time Protection -> The "Scan all downloaded files and attachments" policy must be enabled or the "Block at First Sight" feature will not function. Real-time Protection -> Do not enable the "Turn off real-time protection" policy or the "Block at First Sight" feature will not function.'
  desc 'check', %q(This is applicable to unclassified systems, for other systems this is NA.

Verify the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> MAPS -> "Configure the 'Block at First Sight' feature" is set to "Enabled".
     
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\Software\Policies\Microsoft\Windows Defender\Spynet

Criteria: If the value "DisableBlockAtFirstSeen" is REG_DWORD = 0, this is not a finding.)
  desc 'fix', %q(This is applicable to unclassified systems, for other systems this is NA.

Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> MAPS -> "Configure the 'Block at First Sight' feature" to "Enabled".)
  impact 0.5
  ref 'DPMS Target Microsoft Windows Defender Antivirus'
  tag check_id: 'C-14658r314608_chk'
  tag severity: 'medium'
  tag gid: 'V-213433'
  tag rid: 'SV-213433r569189_rule'
  tag stig_id: 'WNDF-AV-000009'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-14656r314609_fix'
  tag 'documentable'
  tag legacy: ['SV-89843', 'V-75163']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
