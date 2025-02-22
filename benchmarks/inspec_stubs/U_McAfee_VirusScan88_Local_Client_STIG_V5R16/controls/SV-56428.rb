control 'SV-56428' do
  title 'McAfee VirusScan On-Access Scanner All Processes settings actions, When a threat is found must be configured to delete files automatically if first action fails.'
  desc 'Malware may have infected a file that is necessary to the user. By configuring the antivirus software to first attempt cleaning the infected file, availability to the file is not sacrificed. If a cleaning attempt is not successful, however, deleting the file is the only safe option to ensure the malware is not introduced onto the system or network.'
  desc 'check', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select All Processes.

Under the Actions tab, locate the "When a threat is found:" label. Ensure from the "If the first action fails, then perform this action:" pull down menu, "Delete files automatically" is selected.

Criteria:  If  the "Delete files automatically" is selected for "If the first action fails, then perform this action:", this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration\\Default

Criteria:  If the uSecAction does not have a value of 4, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select All Processes.

Under the Actions tab, locate the "When a threat is found:" label. From the "If the first action fails, then perform this action:" pull down menu, select "Delete files automatically". 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49340r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14631'
  tag rid: 'SV-56428r1_rule'
  tag stig_id: 'DTAM111'
  tag gtitle: 'DTAM111-McAfee VirusScan process secondary action'
  tag fix_id: 'F-49144r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
