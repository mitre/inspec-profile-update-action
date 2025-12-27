control 'SV-213435' do
  title 'Windows Defender AV must be configured to only send safe samples for MAPS telemetry.'
  desc 'This policy setting configures behavior of samples submission when opt-in for MAPS telemetry is set. Possible options are: (0x0) Always prompt  (0x1) Send safe samples automatically  (0x2) Never send  (0x3) Send all samples automatically.'
  desc 'check', 'This is applicable to unclassified systems, for other systems this is NA.

Verify the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> MAPS -> "Send file samples when further analysis is required" is set to "Enabled" and "Send safe samples" selected from the drop down box.
     
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Spynet

Criteria: If the value "SubmitSamplesConsent" is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'This is applicable to unclassified systems, for other systems this is NA.

Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> MAPS -> "Send file samples when further analysis is required" to "Enabled" and select "Send safe samples" from the drop down box.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Defender Antivirus'
  tag check_id: 'C-14660r314614_chk'
  tag severity: 'medium'
  tag gid: 'V-213435'
  tag rid: 'SV-213435r569189_rule'
  tag stig_id: 'WNDF-AV-000011'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-14658r314615_fix'
  tag 'documentable'
  tag legacy: ['SV-89887', 'V-75207']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
