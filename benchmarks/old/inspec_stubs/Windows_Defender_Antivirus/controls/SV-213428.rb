control 'SV-213428' do
  title 'Windows Defender AV must be configured to run and scan for malware and other potentially unwanted software.'
  desc 'This policy setting turns off Windows Defender Antivirus. If you enable this policy setting Windows Defender Antivirus does not run and computers are not scanned for malware or other potentially unwanted software. When the setting is Disabled and a third-party antivirus solution is installed, the two applications can both simultaneously try to protect the system. The two AV solutions both attempt to quarantine the same threat and will fight for access to delete the file. Users will see conflicts and the system may lock up until the two solutions finish processing. When the setting is Not Configured and a third-party antivirus solution is installed, both applications co-exist on the system without conflicts.  Defender Antivirus will automatically disable itself and will enable if the third-party solution stops functioning.  When the setting is Not Configured and Defender Antivirus is the only AV solution, Defender AV will run (default state) and receive definition updates.  An administrator account is needed to turn off the service.  A standard user cannot disable the service.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Defender Antivirus >> "Turn off Windows Defender Antivirus" is set to “Not Configured”.

For Windows 10:
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender

Criteria: If the value "DisableAntiSpyware" does not exist, this is not a finding.'
  desc 'fix', 'For Windows 10: Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Defender Antivirus set "Turn off Windows Defender Antivirus" to "Not Configured".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Defender Antivirus'
  tag check_id: 'C-14653r642142_chk'
  tag severity: 'high'
  tag gid: 'V-213428'
  tag rid: 'SV-213428r569189_rule'
  tag stig_id: 'WNDF-AV-000004'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-14651r641862_fix'
  tag 'documentable'
  tag legacy: ['SV-89833', 'V-75153']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
