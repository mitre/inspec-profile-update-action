control 'SV-55403' do
  title 'The Symantec Endpoint Protection client Auto-Protect reload must be configured to stop and reload when the configuration changes.'
  desc 'Antivirus software is the most commonly used technical control for malware threat mitigation. Antivirus software on hosts should be configured to scan all hard drives regularly to identify any file system infections and to scan any removable media, if applicable, before media is inserted into the system. Not scheduling a regular scan of the hard drives of a system and/or not configuring the scan to scan all files and running processes introduces a higher risk of threats going undetected.'
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to the open Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Auto-Protect tab -> Select Advanced -> Under the Changes requiring Auto-Protect reload -> Ensure "Stop and reload Auto-Protect" is selected. 

Criteria:  If "Stop and reload Auto-Protect" is not selected, this is a finding. 

On the machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan

Criteria:  If the value of ConfigRestart is not 1, this is a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to the open Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Auto-Protect tab -> Select Advanced -> Under the Changes requiring Auto-Protect reload -> Select "Stop and reload Auto-Protect".'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-48946r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42675'
  tag rid: 'SV-55403r1_rule'
  tag stig_id: 'DTASEP011'
  tag gtitle: 'DTASEP011'
  tag fix_id: 'F-48260r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
