control 'SV-55365' do
  title 'The Symantec Endpoint Protection client Auto-Protect Advanced Options Floppy Settings must be enabled to scan for boot viruses.'
  desc 'Computer viruses in the early days of personal computing were almost exclusively passed around by floppy disks. Floppy disks would be used to boot the computer and, if infected, would infect the hard drive files, as well. Although floppy drives have fallen out of use, it is still a good security practice, whenever the antivirus software allows, to enable the scanning software to scan a floppy disk.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Protection Technology -> Select Auto-Protect -> Select the Scan Details tab -> Under Scanning, Additional Options -> Select Advanced Scanning and Monitoring -> Under Floppy Settings -> Ensure "Check floppies for boot viruses when accessed" is selected.

Criteria:  If "Check floppies for boot viruses when accessed" is not selected, this is a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan

Criteria:  If the value of ScanFloppyBROnAccess is not 1, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Protection Technology -> Select Auto-Protect -> Select the Scan Details tab -> Under Scanning, Additional Options -> Select Advanced Scanning and Monitoring -> Under Floppy Settings -> Select "Check floppies for boot viruses when accessed".'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48908r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42637'
  tag rid: 'SV-55365r1_rule'
  tag stig_id: 'DTASEP017'
  tag gtitle: 'DTASEP017'
  tag fix_id: 'F-48222r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
