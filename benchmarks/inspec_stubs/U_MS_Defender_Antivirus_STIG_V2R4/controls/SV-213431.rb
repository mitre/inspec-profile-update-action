control 'SV-213431' do
  title 'Microsoft Defender AV must be configured to enable the Automatic Exclusions feature.'
  desc 'This setting allows an administrator to specify if Automatic Exclusions feature for Server SKUs should be turned off.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Exclusions >> "Turn off Auto Exclusions" is set to "Disabled".
     
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Exclusions

Criteria: If the value "DisableAutoExclusions" is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Exclusions >> "Turn off Auto Exclusions" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Defender Antivirus'
  tag check_id: 'C-14656r820140_chk'
  tag severity: 'medium'
  tag gid: 'V-213431'
  tag rid: 'SV-213431r823034_rule'
  tag stig_id: 'WNDF-AV-000007'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-14654r823033_fix'
  tag 'documentable'
  tag legacy: ['SV-89839', 'V-75159']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
