control 'SV-213431' do
  title 'Windows Defender AV must be configured to enable the Automatic Exclusions feature.'
  desc 'Allows an administrator to specify if Automatic Exclusions feature for Server SKUs should be turned off.'
  desc 'check', 'Verify the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Exclusions -> "Turn off Auto Exclusions" is set to "Disabled".
     
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Exclusions

Criteria: If the value "DisableAutoExclusions" is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Exclusions -> "Turn off Auto Exclusions" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Defender Antivirus'
  tag check_id: 'C-14656r314602_chk'
  tag severity: 'medium'
  tag gid: 'V-213431'
  tag rid: 'SV-213431r569189_rule'
  tag stig_id: 'WNDF-AV-000007'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-14654r314603_fix'
  tag 'documentable'
  tag legacy: ['SV-89839', 'V-75159']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
