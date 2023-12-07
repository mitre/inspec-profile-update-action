control 'SV-213445' do
  title 'Windows Defender AV must be configured to always enable real-time protection.'
  desc 'This policy setting turns off real-time protection prompts for known malware detection. Windows Defender Antivirus alerts you when malware or potentially unwanted software attempts to install itself or to run on your computer. If you enable this policy setting Windows Defender Antivirus will not prompt users to take actions on malware detections. If you disable or do not configure this policy setting Windows Defender Antivirus will prompt users to take actions on malware detections.'
  desc 'check', 'Verify the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Real-time Protection -> "Turn off real-time protection" is set to "Disabled" or "Not Configured".
 
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection

Criteria: If the value "DisableRealtimeMonitoring" is REG_DWORD = 0, this is not a finding.

If the value does not exist, this is not a finding.

If the value is 1, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Real-time Protection -> "Turn off real-time protection" to "Disabled" or "Not Configured".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Defender Antivirus'
  tag check_id: 'C-14670r314644_chk'
  tag severity: 'medium'
  tag gid: 'V-213445'
  tag rid: 'SV-213445r569189_rule'
  tag stig_id: 'WNDF-AV-000021'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-14668r314645_fix'
  tag 'documentable'
  tag legacy: ['SV-89907', 'V-75227']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
