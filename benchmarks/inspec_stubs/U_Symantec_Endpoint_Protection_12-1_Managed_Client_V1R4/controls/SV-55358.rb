control 'SV-55358' do
  title 'The Symantec Endpoint Protection client Auto-Protect reload must be configured to stop and reload when the configuration changes.'
  desc 'Antivirus software is the most commonly used technical control for malware threat mitigation. Antivirus software on hosts should be configured to scan all hard drives regularly to identify any file system infections and to scan any removable media, if applicable, before media is inserted into the system. Not scheduling a regular scan of the hard drives of a system and/or not configuring the scan to scan all files and running processes, introduces a higher risk of threats going undetected.'
  desc 'check', 'Server check: From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console: Select Policies -> Double-click the applied policy -> Under Windows Settings, Protection Technology, select Auto-Protect -> Select the Advanced tab -> Under Auto-Protect Reloading and Enablement, When Auto-Protect must be reloaded -> Ensure "Stop and reload Auto-Protect" is selected.

Criteria:  If "Stop and reload Auto-Protect" is not selected, this is a finding.

On the client machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan

Criteria:  If the value of ConfigRestart is not 1, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click on the applied policy -> Under Windows Settings, Protection Technology, select Auto-Protect -> Select the Advanced tab -> Under Auto-Protect Reloading and Enablement, When Auto-Protect must be reloaded -> Select "Stop and reload Auto-Protect".'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48902r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42630'
  tag rid: 'SV-55358r1_rule'
  tag stig_id: 'DTASEP011'
  tag gtitle: 'DTASEP011'
  tag fix_id: 'F-48215r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
