control 'SV-213430' do
  title 'Windows Defender AV must be configured to not exclude files opened by specified processes.'
  desc 'This policy setting allows you to disable scheduled and real-time scanning for any file opened by any of the specified processes. The process itself will not be excluded. To exclude the process use the Path exclusion. Processes should be added under the Options for this setting. Each entry must be listed as a name value pair where the name should be a string representation of the path to the process image. Note that only executables can be excluded. For example a process might be defined as: "c:\\windows\\app.exe". The value is not used and it is recommended that this be set to 0.'
  desc 'check', 'Verify the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Exclusions -> "Process Exclusions" is set to "Disabled" or "Not Configured".
  
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Exclusions

Criteria: If the value "Exclusions_Processes" does not exist, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Exclusions -> "Process Exclusions" to "Disabled" or "Not Configured".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Defender Antivirus'
  tag check_id: 'C-14655r314599_chk'
  tag severity: 'medium'
  tag gid: 'V-213430'
  tag rid: 'SV-213430r569189_rule'
  tag stig_id: 'WNDF-AV-000006'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-14653r314600_fix'
  tag 'documentable'
  tag legacy: ['SV-89837', 'V-75157']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
