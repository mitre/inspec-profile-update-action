control 'SV-55391' do
  title 'The Symantec Endpoint Protection client Auto-Protect Scan Actions for Security Risks must be configured to Quarantine Risk if first action fails.'
  desc 'Malware may have infected a file that is necessary to the user. By configuring the antivirus software to first attempt to delete the infected file, availability to the file is not sacrificed. If a deleting attempt is not successful, however, quarantining the file is the only safe option so as to ensure the malware is not introduced onto the system or network.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Protection Technology -> Select Auto-Protect -> Select the Actions tab -> Under Actions -> Select Security Risks -> Ensure If first action fails is set to "Quarantine Risk". 

Criteria:  If first action fails is not set to "Quarantine Risk", this is a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key: 
32 bit:
HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan\\Expanded
64 bit: 
HKLM\\SOFTWARE\\Wow6432Node\\Symantec\\Symantec Endpoint Protection\\AV\\Storages\\Filesystem\\RealTimeScan\\Expanded

Criteria:  If the value of "SecondAction" is not 1, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Protection Technology -> Select Auto-Protect -> Select the Actions tab -> Under Actions -> Select Security Risks -> Set If first action fails to "Quarantine Risk".'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48933r1_chk'
  tag severity: 'medium'
  tag gid: 'V-42663'
  tag rid: 'SV-55391r1_rule'
  tag stig_id: 'DTASEP042'
  tag gtitle: 'DTASEP042'
  tag fix_id: 'F-48247r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
