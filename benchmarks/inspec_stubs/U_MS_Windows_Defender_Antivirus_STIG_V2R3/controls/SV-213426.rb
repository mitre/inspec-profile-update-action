control 'SV-213426' do
  title 'Windows Defender AV must be configured to block the Potentially Unwanted Application (PUA) feature.'
  desc 'After enabling this feature, PUA protection blocking takes effect on endpoint clients after the next signature update or computer restart. Signature updates take place daily under typical circumstances. PUA will be blocked and automatically quarantined.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Defender Antivirus >> "Configure detection for potentially unwanted applications" is set to "Enabled" and "Block".

Use the Windows Registry Editor to navigate to the following key: 

HKLM\\Software\\Policies\\Microsoft\\Windows Defender

If the value "PUAProtection" does not exist, this is a finding.

If the value "PUAProtection" is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Defender Antivirus >> "Configure Detection for Potentially Unwanted Applications" to "Enabled" and "Block".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Defender Antivirus'
  tag check_id: 'C-14651r314587_chk'
  tag severity: 'high'
  tag gid: 'V-213426'
  tag rid: 'SV-213426r569189_rule'
  tag stig_id: 'WNDF-AV-000001'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-14649r314588_fix'
  tag 'documentable'
  tag legacy: ['SV-89827', 'V-75147']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
