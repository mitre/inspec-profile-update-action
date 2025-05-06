control 'SV-68107' do
  title 'The Symantec Endpoint Protection client weekly scheduled scan actions for when a security risk has been detected must be configured to Delete Risk as first action.'
  desc 'Malware may have infected a file that is necessary to the user. By configuring the antivirus software to first attempt cleaning the infected file, availability to the file is not sacrificed. If a cleaning attempt is not successful, however, deleting the file is the only safe option so as to ensure the malware is not introduced onto the system or network.'
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Select the Actions tab -> Under Actions -> Select Security Risks -> Observe the First action and the If first action fails boxes -> Ensure First action is set to "Delete Risk". 

Criteria:  If First action is not set to "Delete Risk", this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Select the Actions tab -> Under Actions -> Select Security Risks -> Observe the First action and the If first action fails boxes -> Set First action to "Delete Risk".'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48995r2_chk'
  tag severity: 'medium'
  tag gid: 'V-42723'
  tag rid: 'SV-68107r1_rule'
  tag stig_id: 'DTASEP069'
  tag gtitle: 'DTASEP069'
  tag fix_id: 'F-48309r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
