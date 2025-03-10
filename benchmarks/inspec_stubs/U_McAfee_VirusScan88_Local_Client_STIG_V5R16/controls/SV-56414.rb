control 'SV-56414' do
  title 'McAfee VirusScan On-Demand scan actions, When a threat is found must be configured to delete files automatically if first action fails.'
  desc 'Malware may have infected a file that is necessary to the user. By configuring the antivirus software to first attempt cleaning the infected file, availability to the file is not sacrificed. If a cleaning attempt is not successful, however, deleting the file is the only safe option so as to ensure the malware is not introduced onto the system or network.'
  desc 'check', %q(Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task,  with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Actions tab, locate the "When a threat is found:" label. Ensure that from the "If the first action fails, then perform this action:" pull down menu, "Delete" is selected.

Criteria:  If "Delete" is selected for "If the first action fails, then perform this action:", this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\Software\McAfee\ (32-bit)
HKLM\Software\Wow6432Node\McAfee\ (64-bit)
DesktopProtection\Tasks

Under the DesktopProtection\Tasks, and with the assistance of the System Administrator, review each GUID key's szTaskName to find the GUID key associated with weekly on-demand client scan task. 

Criteria:  If, under the applicable GUID key, the uSecAction does not have a value of 4, this is a finding.)
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task,  with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Actions tab, locate the "When a threat is found:" label. From the "If the first action fails, then perform this action:" pull down menu, select "Delete". 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49322r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6617'
  tag rid: 'SV-56414r1_rule'
  tag stig_id: 'DTAM057'
  tag gtitle: 'DTAM057-McAfee VirusScan secondary action'
  tag fix_id: 'F-49126r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
