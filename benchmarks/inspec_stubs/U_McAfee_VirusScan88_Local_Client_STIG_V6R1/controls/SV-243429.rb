control 'SV-243429' do
  title 'McAfee VirusScan On-Demand scan actions, When an unwanted program is found must be configured to clean files automatically as first action.'
  desc 'Malware may have infected a file that is necessary to the user. By configuring the antivirus software to first attempt cleaning the infected file, availability to the file is not sacrificed. If a cleaning attempt is not successful, however, deleting the file is the only safe option to ensure the malware is not introduced onto the system or network.'
  desc 'check', %q(Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task,  with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Actions tab, locate the "When an unwanted program is found:" label. Ensure for the "Perform this action first:" pull down menu, "Clean" is selected.

Criteria:  If "Clean" is selected for "Perform this action first", this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\Software\McAfee\ (32-bit)
HKLM\Software\Wow6432Node\McAfee\ (64-bit)
DesktopProtection\Tasks

Under the DesktopProtection\Tasks, and with the assistance of the System Administrator, review each GUID key's szTaskName to find the GUID key associated with weekly on-demand client scan task. 

Criteria:  If, under the applicable GUID key, the uAction_Program does not have a value of 5, this is a finding.)
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task,  with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Actions tab, locate the "When an unwanted program is found:" label. For the "Perform this action first:" pull down menu, select "Clean".


Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46704r722624_chk'
  tag severity: 'medium'
  tag gid: 'V-243429'
  tag rid: 'SV-243429r722626_rule'
  tag stig_id: 'DTAM155'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-46661r722625_fix'
  tag 'documentable'
  tag legacy: ['V-42559', 'SV-55287']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
