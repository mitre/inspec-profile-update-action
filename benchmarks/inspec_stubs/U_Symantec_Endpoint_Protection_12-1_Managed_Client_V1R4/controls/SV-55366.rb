control 'SV-55366' do
  title 'The Symantec Endpoint Protection client Auto-Protect Advanced Options Floppy Settings must be configured to check floppies when system shuts down.'
  desc 'Computer viruses in the early days of personal computing were almost exclusively passed around by floppy disks. Floppy disks would be used to boot the computer and, if infected, would infect the hard drive files, as well. Although floppy drives have fallen out of use, it is still a good security practice, whenever the antivirus software allows, to enable the scanning software to scan a floppy disk at shutdown.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Protection Technology, select Auto-Protect -> Select the Advanced tab -> Under Startup and Shutdown -> Ensure "Check floppies when the computer shuts down" is selected.

Criteria:  If "Check floppies when the computer shuts down" is not selected, this is a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan

Criteria:  If the value of SkipShutDownFloppyCheck is not 0, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Protection Technology, select Auto-Protect -> Select the Advanced tab -> Under Startup and Shutdown -> Select "Check floppies when the computer shuts down".'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48909r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42638'
  tag rid: 'SV-55366r1_rule'
  tag stig_id: 'DTASEP018'
  tag gtitle: 'DTASEP018'
  tag fix_id: 'F-48223r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
