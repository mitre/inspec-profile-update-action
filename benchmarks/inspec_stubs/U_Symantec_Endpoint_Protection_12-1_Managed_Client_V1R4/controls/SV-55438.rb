control 'SV-55438' do
  title 'The Symantec Endpoint Protection client weekly scheduled scan actions for when malware has been detected must be configured to Clean Risk as first action.'
  desc 'Malware may have infected a file that is necessary to the user. By configuring the antivirus software to first attempt cleaning the infected file, availability to the file is not sacrificed. If a cleaning attempt is not successful, however, deleting the file is the only safe option so as to ensure the malware is not introduced onto the system or network.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Select the Actions tab -> Under Actions -> Select Malware -> Observe the First action and the If first action fails boxes -> Ensure First action is set to "Clean Risk".

Criteria:  If First action is not set to "Clean Risk", this is a finding.

On the client machine use the Windows Registry Editor to navigate to the following key:
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Scheduler\\{SID}\\Custom Tasks\\{Scan ID}\\Malware
64 bit: 
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Scheduler\\{SID}\\Custom Tasks\\{Scan ID}\\Malware

Criteria: If the value of "FirstAction" is not 5, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click on the Weekly Scan -> Select the Actions tab -> Under Actions -> Select Malware -> Observe the First action and the If first action fails boxes -> Set First action to "Clean Risk".'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48982r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42710'
  tag rid: 'SV-55438r1_rule'
  tag stig_id: 'DTASEP056'
  tag gtitle: 'DTASEP056'
  tag fix_id: 'F-48296r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
