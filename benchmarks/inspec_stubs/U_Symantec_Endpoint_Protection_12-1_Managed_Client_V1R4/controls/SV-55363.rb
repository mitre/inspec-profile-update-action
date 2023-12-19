control 'SV-55363' do
  title 'The Symantec Endpoint Protection client Auto-Protect Backup Option must be disabled to prevent backing up infected files before attempting to repair them.'
  desc "For antivirus software to be effective, it must be running at all times, beginning from the point of the system's initial startup. Otherwise, the risk is greater for viruses, Trojans, and other malware infecting the system during that startup phase."
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Protection Technology -> Select Auto-Protect -> Select the Actions -> Under Remediation -> Ensure "Back up files before attempting to repair them" is NOT selected.

Criteria:  If "Back up files before attempting to repair them" is selected, this is a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan

Criteria:  If the value of BackupToQuarantine is not 0, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Protection Technology -> Select Auto-Protect -> Select the Actions -> Under Remediation -> Ensure "Back up files before attempting to repair them" is NOT selected.'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48906r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42635'
  tag rid: 'SV-55363r1_rule'
  tag stig_id: 'DTASEP015'
  tag gtitle: 'DTASEP015'
  tag fix_id: 'F-48219r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
