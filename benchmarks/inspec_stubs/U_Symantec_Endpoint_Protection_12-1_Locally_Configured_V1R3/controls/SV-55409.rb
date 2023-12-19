control 'SV-55409' do
  title 'The Symantec Endpoint Protection client Auto-Protect Advanced Options Floppy Settings must be enabled to scan for boot viruses.'
  desc 'Computer viruses in the early days of personal computing were almost exclusively passed around by floppy disks. Floppy disks would be used to boot the computer and, if infected, would infect the hard drive files, as well. Although floppy drives have fallen out of use, it is still a good security practice, whenever the antivirus software allows, to enable the scanning software to scan a floppy disk for boot viruses.'
  desc 'check', 'GUI check:  Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Auto-Protect tab -> Select Advanced -> Under Additional advanced options -> Select Floppies -> Under Floppy settings -> Ensure "Check floppies for boot viruses when accessed" is selected. 

Criteria:  If "Check floppies for boot viruses when accessed" is not selected, this is a finding. 

On the machine use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan

Criteria:  If the value of ScanFloppyBROnAccess is not 1, this is a finding.'
  desc 'fix', 'Locate the Symantec Endpoint Protection icon in the system tray. Double-click the icon to open the Symantec Endpoint Protection configuration screen. On the left hand side, select Change settings -> Under Virus and Spyware Protection -> Select Configure Settings -> Under the Auto-Protect tab -> Select Advanced -> Under Additional advanced options -> Select Floppies -> Under Floppy settings -> Select "Check floppies for boot viruses when accessed".'
  impact 0.5
  ref 'DPMS Target Symantec AntiVirus Locally Configured Client'
  tag check_id: 'C-48952r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42681'
  tag rid: 'SV-55409r1_rule'
  tag stig_id: 'DTASEP017'
  tag gtitle: 'DTASEP017'
  tag fix_id: 'F-48266r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
