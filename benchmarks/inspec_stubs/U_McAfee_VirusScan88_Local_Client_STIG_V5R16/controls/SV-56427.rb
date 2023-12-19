control 'SV-56427' do
  title 'McAfee VirusScan On-Access Scanner All Processes settings actions, When a threat is found must be configured to clean files automatically as first action.'
  desc 'Malware may have infected a file that is necessary to the user. By configuring the antivirus software to first attempt cleaning the infected file, availability to the file is not sacrificed. If a cleaning attempt is not successful, however, deleting the file is the only safe option to ensure the malware is not introduced onto the system or network.'
  desc 'check', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select All Processes.

Under the Actions tab, locate the "When a threat is found:" label. Ensure for the "Perform this action first:" pull down menu, "Clean files automatically" is selected.

Criteria:  If "Clean files automatically" is selected from "Perform this action first", this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration\\Default

Criteria:  If the uAction does not have a value of 5, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select All Processes.

Under the Actions tab, locate the "When a threat is found:" label. For the "Perform this action first:" pull down menu, select "Clean files automatically". 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49339r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14630'
  tag rid: 'SV-56427r1_rule'
  tag stig_id: 'DTAM110'
  tag gtitle: 'DTAM110-McAfee VirusScan process primary action'
  tag fix_id: 'F-49143r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
