control 'SV-55377' do
  title 'The Symantec Endpoint Protection client Auto-Protect Scan Actions for Malware must be configured to Clean Risk as the first action upon detection.'
  desc 'Malware may have infected a file that is necessary to the user. By configuring the antivirus software to first attempt cleaning the infected file, availability to the file is not sacrificed. If a cleaning attempt is not successful, however, deleting the file is the only safe option so as to ensure the malware is not introduced onto the system or network.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Protection Technology -> Select Auto-Protect -> Select the Actions tab -> Under Actions -> Select Malware -> Ensure First action is set to "Clean Risk".

Criteria:  If First action is not set to "Clean Risk", this is a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan\\Malware
64 bit:
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan\\Malware

Criteria:  If the value of "FirstAction" is not 5, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Protection Technology -> Select Auto-Protect -> Select the Actions tab -> Under Actions -> Select Malware -> Set First action to "Clean Risk".'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48919r2_chk'
  tag severity: 'medium'
  tag gid: 'V-42649'
  tag rid: 'SV-55377r1_rule'
  tag stig_id: 'DTASEP028'
  tag gtitle: 'DTASEP028'
  tag fix_id: 'F-48233r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
